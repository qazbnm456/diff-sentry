"""Runs INSIDE the container (stdlib only). Reads a JSON list of command texts on stdin and, for each, reports what a real
`bash` and a real `dash` did with it: whether the downloaded script ran (unmodified), what was fetched, what else was called.

The stubs: `curl`/`wget` log their arguments and proxy variables and print a script that logs a fixed marker line when a shell
(or an interpreter, for `python3 -`) runs it; `nc`, `evil`, `docker`, ... only log that they were called; files a payload might
name (`./evil`, `evil.sh`, `x.sh`) are planted in the working directory and log too. The stubs are restored before every run,
because a candidate may delete them."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

MARKER = "SINK-RAN abcdefghijklmnopqrstuvwxyz0123456789"      # letters, so a stage that rewrites the stream changes it
STUB = pathlib.Path("/tmp/stub")
PLANTED = pathlib.Path("/tmp/x")                               # what an `export PATH=/tmp/x:$PATH` line would put first
DOWNLOAD = ('#!/bin/sh\necho "FETCH $0 $* PROXY=${HTTP_PROXY}${http_proxy}${HTTPS_PROXY}${https_proxy}${ALL_PROXY}" >> "$ORACLE_LOG"\n'
            f'echo \'echo {MARKER} >> "$ORACLE_LOG"\'\n')
LOGGING = '#!/bin/sh\necho "OTHER $0 $*" >> "$ORACLE_LOG"\n'
SUDO = '''#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -u|-g|-h|-p|-C|-U|-D|-R|-T|-r|-t) shift 2;;
    --) shift; break;;
    -*) shift;;
    *=*) export "$1"; shift;;
    *) break;;
  esac
done
exec "$@"
'''
SU = '#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -c) shift; exec sh -c "$1";; *) shift;; esac; done\n'
# An interpreter: a program from stdin (or /dev/fd) is "the downloaded script ran" when it holds the marker; its own code
# (-c, -e, a file) is something else.
INTERP = f'''#!/bin/sh
src=stdin
while [ $# -gt 0 ]; do
  case "$1" in
    -c|-e|-m|-r|-E|-f) echo "OTHER $0 own-code" >> "$ORACLE_LOG"; exit 0;;
    -W|-X) shift 2;;
    -) src=stdin; shift; break;;
    -*) shift;;
    /dev/fd/*|/proc/self/fd/*) src="$1"; shift; break;;
    *) echo "OTHER $0 script $1" >> "$ORACLE_LOG"; exit 0;;
  esac
done
# what is left are the ARGUMENTS the program is given (Poetry documents a few); anything else chooses where it gets its code
while [ $# -gt 0 ]; do
  case "$1" in
    --version) shift 2;;
    --uninstall|--force|--preview|--yes|--help|-y|-h) shift;;
    *) echo "OTHER $0 argument $1" >> "$ORACLE_LOG"; exit 0;;
  esac
done
if [ "$src" = stdin ]; then in=$(cat); else in=$(cat "$src"); fi
case "$in" in *"{MARKER}"*) echo "{MARKER}" >> "$ORACLE_LOG";; *SINK-RAN*) echo "SINK-RAN modified" >> "$ORACLE_LOG";; esac
'''
LOGGED = ("nc", "evil", "docker", "ssh", "npx", "uvx", "pipx", "strace", "nsenter", "chroot", "podman", "kubectl", "bunx", "pnpx",
          "flatpak", "snap", "sg", "poetry", "uv", "pipenv", "conda", "mise", "direnv", "asdf", "nix", "yarn", "npm", "bundle",
          "watch", "pyenv", "rbenv", "setpriv", "fakeroot", "toybox")


def restore_stubs() -> None:
    STUB.mkdir(exist_ok=True)
    PLANTED.mkdir(exist_ok=True)
    files = {"curl": DOWNLOAD, "wget": DOWNLOAD, "sudo": SUDO, "doas": SUDO, "pkexec": SUDO, "su": SU}
    files.update({name: LOGGING for name in LOGGED})
    files.update({name: INTERP for name in ("python3", "python", "perl", "ruby", "node", "nodejs", "php")})
    for name, body in files.items():
        path = STUB / name
        if not path.exists() or path.read_text() != body:
            path.write_text(body)
        path.chmod(0o755)
    for name in ("sh", "bash", "curl", "wget", "tee", "cat"):
        path = PLANTED / name
        if not path.exists():
            path.write_text(LOGGING)
        path.chmod(0o755)


def run(text: str, shell: str) -> str:
    restore_stubs()
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "log")
        pathlib.Path(log).write_text("")
        for name in ("evil", "evil.sh", "x", "x.sh", "e.py", "f", "bin/evil", "a/b", "scripts/evil", "evil.run", "evil.json",
                     "evil.sh-bak", "evil.ksh", "bin/@evil", "dir/é"):
            planted = pathlib.Path(d) / name
            planted.parent.mkdir(exist_ok=True)
            planted.write_text('#!/bin/sh\necho "OTHER $0" >> "$ORACLE_LOG"\n')
            planted.chmod(0o755)
        script = os.path.join(d, "cand.sh")
        # aliases are off in a non-interactive bash unless asked for; a payload that relies on one is asking
        pathlib.Path(script).write_text(("shopt -s expand_aliases\n" if shell == "bash" else "") + text)
        env = {"PATH": f"{STUB}:/usr/bin:/bin", "ORACLE_LOG": log, "HOME": d, "SHELL": "/bin/sh"}
        try:
            subprocess.run([shell, script], env=env, cwd=d, capture_output=True, timeout=3, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pass
        return pathlib.Path(log).read_text()


out = []
for text in json.load(sys.stdin):
    row = {}
    for shell in ("bash", "dash"):
        lines = run(text, shell).splitlines()
        row[shell] = {"sink_ran": MARKER in lines,                     # the EXACT line: a candidate cannot spell it by accident
                      "fetches": [ln for ln in lines if ln.startswith("FETCH")],
                      "other": [ln for ln in lines if ln.startswith("OTHER")],
                      "modified": any(ln.startswith("SINK-RAN") and ln != MARKER for ln in lines)}
    out.append(row)
print(json.dumps(out))

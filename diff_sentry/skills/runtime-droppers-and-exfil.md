---
name: runtime-droppers-and-exfil
description: Code that fetches and runs a second stage, spawns hidden processes, or sends secrets out — how to follow a source to its sink in application and script code.
---

# Code that fetches, spawns or sends

Once a payload runs, it usually does one of three things: fetch and run a second stage, start a process that
outlives its parent, or collect secrets and send them somewhere. The first stage is small; the evidence is a
source joined to a sink.

## Footprints

**Fetch and run**
- `curl ... | sh`, `wget -qO- ... | bash`, `irm ... | iex`, `Invoke-WebRequest ... | Invoke-Expression`.
- A network read written to disk and then executed or `require`d: `https.get(url).pipe(createWriteStream(p))`
  followed by `spawn`/`exec`/`require(p)`; Python `urllib` + `exec`/`subprocess`.
- Hosts chosen to be hard to block or attribute: IPFS gateways, raw IPs, dev tunnels (ngrok, trycloudflare),
  paste and webhook services, a freshly registered lookalike domain.

**Hidden execution**
- `spawn(..., {detached: true}).unref()`, `child_process` with `stdio: 'ignore'`, `node -e <string>`,
  `eval`/`new Function` on a decoded or fetched string, `exec(compile(...))`.
- A decoder (base64, XOR, char codes, string-array) whose output flows into one of the above.

**Secret collection and exfiltration**
- Sources (they count when they reach any sink below, or when the read has no reason in the change's purpose;
  passing the environment to a child process or loading `.env` is ordinary): `process.env`/`os.environ` read
  whole, `printenv`, `~/.npmrc`, `~/.aws/credentials`, `~/.ssh`,
  `/proc/<pid>/environ` or `/proc/<pid>/mem`, browser profile and wallet paths, `gh auth token`, secret
  scanners (`trufflehog filesystem`).
- Sinks: `curl -d @-`, `--data-binary`, `fetch(..., {method: 'POST'})`, DNS lookups with data in the name,
  creating a public repository or gist, writing to the CI log.
- Local AI CLIs driven with permission-skipping flags and a prompt to inventory secrets.

## Verify (read, never run)

1. Find every sink (exec, spawn, eval, network send, file write followed by run).
2. Walk backwards from each sink: where does its argument come from? A constant the repository controls, a
   value from configuration, or something fetched, decoded or read from a secret location?
3. Decode what is encoded and scan it with `decoded_from`. A decoded URL or command is evidence of the change.
4. Ask whether the code's stated purpose needs the sink. A CLI that installs a tool needs a download; a date
   formatting helper does not need `child_process`.

## Look-alikes (benign, seen in practice)

- An editor or agent host that spawns detached helper processes by design.
- A DevTools or test client fetching `127.0.0.1` / `localhost`.
- A repro in an issue that uses `node -e` to show a bug.
- A deploy step sending a secret to the vendor CLI the repository already uses.
- An official installer line in a project's own README (`curl -LsSf https://astral.sh/uv/install.sh | sh` in
  uv's docs): the host is the project's own.

## Rules that fire here

`curl-pipe-shell`, `remote-fetch-to-disk`, `detached-process-spawn`, `inline-code-exec`,
`dynamic-code-eval`, `data-exfiltration`, `exfil-infrastructure`, `content-addressed-host`,
`dev-tunnel-endpoint`, `raw-ip-url`, `obfuscated-payload`. Sub-floor ones (`dynamic-code-eval`, tunnels,
IPFS) are corroborators: judge them by where their input comes from.

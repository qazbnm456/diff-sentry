---
name: developer-autorun
description: "Code that runs on a developer's machine without a command: VS Code tasks on folder open, devcontainers, git hooks, `.envrc`, config files lint and build tools execute, and scripts disguised as fonts or images."
---

# Developer-machine autorun and tool configs

A developer who clones and opens a repository runs code they never typed: the editor's folder-open tasks, the devcontainer's setup commands, git hooks, `direnv`, and every JavaScript config their linter, bundler or test runner loads. An attack here compromises whoever opens the project. Public archetypes: Contagious Interview (`.vscode/tasks.json` with `runOn: folderOpen` running `curl | sh`, or `node` on a fake `.woff2`), PolinRider (obfuscated JavaScript appended after whitespace to `postcss.config.mjs`, `tailwind.config.js`, `eslint.config.*`, `next.config.mjs`; history amended with original dates; `config.bat` added to `.gitignore`). One change can combine all of it: a real feature as cover, mock `api.js` files padded past the viewport, `package.json` scripts rewritten to `node api.js && ...`, an obfuscated tail on `eslint.config.js`, a `.ttf` that is JavaScript, a 500-line `tasks.json` rewrite hiding one folder-open task that runs the `.ttf`, and `settings.json` switching automatic tasks on and the terminal off.

## Footprints

**Triggers**
- `.vscode/tasks.json` or a `.code-workspace` task with `"runOptions": {"runOn": "folderOpen"}`; often with `"reveal": "never"`, `"echo": false`, `"close": true`, `"focus": false`, a label that blends in (`eslint-check`, `env`, `lint on open`), per-OS commands.
- `.vscode/settings.json`: `"task.allowAutomaticTasks": true | "on"`; visibility killers (`"terminal.integrated.hideOnStartup": "always"`, `"debug.openDebug": "neverOpen"`); interpreter or terminal paths pointing into the repository; agent auto-approval (`chat.tools.autoApprove`, `chat.tools.terminal.autoApprove` entries).
- `.devcontainer/devcontainer.json`: `initializeCommand` (runs on the HOST), `postCreateCommand`, `postStartCommand`, `postAttachCommand`.
- Git hooks and their installers (`.husky/*`, `core.hooksPath`, `.pre-commit-config.yaml` with a `local` repo running a script), `.envrc`.

**Carriers**
- A config a tool executes, with code after its final `export default ...;` / `module.exports = ...;`, a `createRequire(import.meta.url)` plus `var require`/`var module` or `global['x'] = require` shims, or a javascript-obfuscator body (`while(!![])`, `['push'](...['shift']())`, hex-indexed calls `F(0x1f2)`).
- A "font" or "image" (`.ttf`, `.woff2`, `.png` and the like) whose content is text: a real one is binary and shows no patch. Any runtime handed such a file (`node public/fonts/x.woff2`) is a loader.
- A new small source file (a mock, a helper) with a long line padded hundreds of spaces to the right.

**Concealment specific to this world**
- `.gitignore` gaining a file the attacker's tooling drops (`config.bat`, `temp_auto_push.bat`).
- A whole-file rewrite (reformatting, reordering) that buries one new entry.

## Verify (read, never run)

1. You hold a patch, not the file. Rebuild the new side of each `.vscode/*.json`, `.code-workspace` and `devcontainer.json` (context and `+` lines, `-` lines dropped) and parse it as JSONC (comments allowed). If it does not parse (a hunk shows part of the file), search the new side for `runOn`, `folderOpen`, `command`, `args` and `allowAutomaticTasks` instead. List every task: label, `command` + `args`, `runOn`, presentation flags. List every command field of the devcontainer.
2. For each command, resolve the file it runs against the change's file list. Is it added by this change? Is its extension a font or image? Read it.
3. For each tool config the change touches: is there anything after the final export? Any line longer than a few hundred characters, or with a long whitespace run? Any obfuscator signature?
4. Compare the label and placement of a new task with the repository's other tasks: a payload task imitates them.

## Look-alikes (benign, seen in practice)

- Folder-open tasks that start a watcher (`npm run watch`) in a project that already uses them.
- `postCreateCommand: npm ci` / `pip install -e .` in a devcontainer.
- Husky installing a lint-staged hook.
- Minified vendor files (terser/esbuild write `!0`, `for(;;)`, never `!![]`).
- Git LFS pointer files under a binary name (three lines: `version`, `oid sha256:`, `size`).

## Rules that fire here

`vscode-autorun`, `run-entry-new-file`, `asset-run-as-code`, `binary-name-holds-text`, `obfuscated-dev-config`, `obfuscated-string-array`, `obfuscated-identifiers`, `diff-viewport-evasion`, `high-entropy-blob`. No rule reads: devcontainer commands, git hooks, `.envrc`, visibility-killing settings, agent auto-approval settings, `.gitignore` additions, code after a config's final export when it is not obfuscated. Those are yours to read.

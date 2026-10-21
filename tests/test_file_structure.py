"""The file-structure rules (`indicators.scan_files`) and the two text rules written with them (`obfuscated-string-array`, `asset-run-as-code`): the shape of a dev-machine loader pushed with ordinary work.

Every positive case is synthetic and inert (no real payload): the rules read structure, not behaviour."""

from __future__ import annotations

import pytest

from diff_sentry.indicators import scan_change, scan_files, scan_indicators

# javascript-obfuscator's machinery with mangled names and no `_0x`: the rotation loop and the push/shift.
_STRING_ARRAY = ("(function(a,b){var c=d;while(!![]){try{var e=parseInt(c(0x1a))/0x1;if(e===b)break;"
                 "else a['push'](a['shift']());}catch(f){a['push'](a['shift']());}}}(g,0x3f));")


def _event(*files, kind="pull_request"):
    return {"repo": "acme/app", "kind": kind, "number": 7, "author": "dev", "title": "Add feature", "body": "",
            "files": [{"filename": n, "status": s, "additions": sum(1 for line in p.split("\n") if line.startswith("+")),
                       "deletions": 0, "patch": p} for n, s, p in files]}


def _rules(hits, rule=None):
    return sorted((h.rule, h.severity, h.location) for h in hits if rule is None or h.rule == rule)


# ── obfuscated-string-array ─────────────────────────────────────────────────────────────────────────

def test_string_array_found_without_hex_names():
    hits = scan_indicators("+" + _STRING_ARRAY)
    assert ("obfuscated-string-array", "high") in {(h.rule, h.severity) for h in hits}


def test_string_array_by_hex_index_calls():
    text = "while(!![]){break}" + "".join(f"x=F(0x{i:x});" for i in range(20))
    assert any(h.rule == "obfuscated-string-array" for h in scan_indicators(text))


@pytest.mark.parametrize("text", [
    "for(;;){if(!0)break}var a=[1,2];a.push(a.shift());",              # what a minifier writes
    "while(!![]){break}" + "".join(f"x=F(0x{i:x});" for i in range(19)),  # one decoder call short
    "a['push'](a['shift']());" * 3,                                       # rotation without the loop
])
def test_string_array_negatives(text):
    assert not any(h.rule == "obfuscated-string-array" for h in scan_indicators(text))


# ── asset-run-as-code ───────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "node public/fonts/fa-solid-400.woff2",
    '"command": "(command -v node && node ./x/fonts/fa-brands-400.ttf) || true"',
    "bun run --silent assets/logo.png",
    "deno run -A ./icon.ico",
])
def test_asset_run_as_code(text):
    hits = [h for h in scan_indicators(text) if h.rule == "asset-run-as-code"]
    assert hits and hits[0].severity == "critical"


@pytest.mark.parametrize("text", [
    "node scripts/build-fonts.mjs public/fonts/fa.ttf",   # a script that takes a font as its argument
    "cp node_modules/x/fa.ttf public/fonts/",
    "nodejs-fonts.ttf",
    "node x.ttfx",
])
def test_asset_run_as_code_negatives(text):
    assert not any(h.rule == "asset-run-as-code" for h in scan_indicators(text))


# ── binary-name-holds-text ──────────────────────────────────────────────────────────────────────────

def test_text_under_a_font_name():
    hits = scan_files(_event(("public/fonts/fa-brands-400.ttf", "added", "@@ -0,0 +1 @@\n+(function(){})();")))
    assert _rules(hits) == [("binary-name-holds-text", "high", "public/fonts/fa-brands-400.ttf")]


@pytest.mark.parametrize(("name", "patch"), [
    ("public/fonts/fa.ttf", ""),                                                  # a real font: no patch
    ("assets/logo.png", "@@ -0,0 +1,3 @@\n+version https://git-lfs.github.com/spec/v1\n+oid sha256:" + "4d" * 32 + "\n+size 48212"),
    ("assets/logo.svg", "@@ -0,0 +1 @@\n+<svg xmlns='http://www.w3.org/2000/svg'/>"),
])
def test_binary_name_negatives(name, patch):
    assert not scan_files(_event((name, "added", patch)))


# ── vscode-autorun ──────────────────────────────────────────────────────────────────────────────────

_TASK = ('@@ -0,0 +1,6 @@\n+{"version": "2.0.0", "tasks": [{\n+  "label": "lint",\n+  "type": "shell",\n'
         '+  "command": "node ./tools/lint.js",\n+  "runOptions": {"runOn": "folderOpen"}\n+}]}')


def test_folder_open_task_and_consent():
    hits = scan_files(_event((".vscode/tasks.json", "modified", _TASK),
                             (".vscode/settings.json", "modified", '@@ -1 +1,2 @@\n {\n+  "task.allowAutomaticTasks": "on",')))
    assert _rules(hits, "vscode-autorun") == [("vscode-autorun", "high", ".vscode/settings.json"),
                                              ("vscode-autorun", "high", ".vscode/tasks.json")]


@pytest.mark.parametrize(("name", "patch"), [
    (".vscode/tasks.json", '@@ -1 +1 @@\n+  "runOptions": {"runOn": "worktreeCreated"}'),
    (".vscode/tasks.json", '@@ -1 +0,0 @@\n-  "runOptions": {"runOn": "folderOpen"}'),          # removing one
    ("docs/tasks.md", '@@ -0,0 +1 @@\n+  "runOptions": {"runOn": "folderOpen"}'),             # not a VS Code file
    (".vscode/settings.json", '@@ -1 +1 @@\n+  "task.allowAutomaticTasks": "off"'),
])
def test_vscode_autorun_negatives(name, patch):
    assert not _rules(scan_files(_event((name, "modified", patch))), "vscode-autorun")


# ── run-entry-new-file ──────────────────────────────────────────────────────────────────────────────

def _pkg(*lines):
    return "@@ -1,3 +1,3 @@\n" + "\n".join(lines)


def test_existing_script_rewritten_to_run_a_new_file_first():
    hits = scan_files(_event(
        ("test/sanity/package.json", "modified",
         _pkg('-    "start": "node ./out/index.js"', '+    "start": "node api.js && node ./out/index.js"')),
        ("test/sanity/api.js", "added", "@@ -0,0 +1 @@\n+export const api = {};")))
    assert _rules(hits) == [("run-entry-new-file", "high", "test/sanity/package.json")]


def test_lifecycle_hook_running_a_new_file_is_high():
    hits = scan_files(_event(("package.json", "modified", _pkg('+    "postinstall": "node scripts/setup.cjs"')),
                             ("scripts/setup.cjs", "added", "@@ -0,0 +1 @@\n+module.exports = {};")))
    assert _rules(hits) == [("run-entry-new-file", "high", "package.json")]


def test_new_script_for_a_new_file_is_only_medium():
    # The honest shape: a codegen script and its npm entry, added together.
    hits = scan_files(_event(("package.json", "modified", _pkg('+    "gen:icons": "node scripts/gen-icons.mjs"')),
                             ("scripts/gen-icons.mjs", "added", "@@ -0,0 +1 @@\n+export {};")))
    assert _rules(hits) == [("run-entry-new-file", "medium", "package.json")]


def test_folder_open_task_running_a_new_file_is_high():
    task = _TASK.replace("node ./tools/lint.js", "node ./tools/check.js")
    hits = scan_files(_event((".vscode/tasks.json", "modified", task),
                             ("tools/check.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert ("run-entry-new-file", "high", ".vscode/tasks.json") in _rules(hits)


@pytest.mark.parametrize("files", [
    # the script names a file the change does not add
    [("package.json", "modified", _pkg('+    "start": "node api.js && node ./out/index.js"'))],
    # the new file is added somewhere else than where the script resolves it
    [("test/sanity/package.json", "modified", _pkg('+    "start": "node api.js"')),
     ("api.js", "added", "@@ -0,0 +1 @@\n+;")],
    # a removed script line is not a run entry
    [("package.json", "modified", _pkg('-    "start": "node api.js"')), ("api.js", "added", "@@ -0,0 +1 @@\n+;")],
])
def test_run_entry_negatives(files):
    assert not _rules(scan_files(_event(*files)), "run-entry-new-file")


# ── obfuscated-dev-config ───────────────────────────────────────────────────────────────────────────

def test_obfuscation_appended_to_a_dev_config_is_critical():
    patch = "@@ -10,2 +10,3 @@\n export default config;\n+" + _STRING_ARRAY
    hits = scan_files(_event(("eslint.config.js", "modified", patch)))
    assert _rules(hits) == [("obfuscated-dev-config", "critical", "eslint.config.js")]


@pytest.mark.parametrize(("name", "patch"), [
    ("eslint.config.js", "@@ -1,2 +1 @@\n-" + _STRING_ARRAY + "\n export default config;"),  # cleaning it up
    ("src/vendor/lib.js", "@@ -0,0 +1 @@\n+" + _STRING_ARRAY),                               # not a dev config
])
def test_obfuscated_dev_config_negatives(name, patch):
    assert not _rules(scan_files(_event((name, "modified", patch))), "obfuscated-dev-config")


# ── wiring ──────────────────────────────────────────────────────────────────────────────────────────

def test_scan_change_carries_the_file_structure_rules():
    hits = scan_change(_event(("public/fonts/a.woff2", "added", "@@ -0,0 +1 @@\n+require('x')")))
    assert "binary-name-holds-text" in {h.rule for h in hits}


def test_a_rule_that_raises_is_a_finding(monkeypatch):
    import diff_sentry.indicators as ind

    def boom(f, added):
        raise RuntimeError("x")

    monkeypatch.setattr(ind, "_file_structure_hits", boom)
    hits = scan_files(_event(("a.js", "added", "+1")))
    assert _rules(hits) == [("scanner-error", "high", "a.js")]


def test_hit_ids_are_stable():
    ev = _event(("public/fonts/a.ttf", "added", "@@ -0,0 +1 @@\n+x()"))
    assert [h.id for h in scan_files(ev)] == [h.id for h in scan_files(ev)]


# ── each spelling the rules must read ─────────────────────────────────────────────────────────────────

def test_a_forged_lfs_line_does_not_exempt_a_script():
    patch = ("@@ -0,0 +1,3 @@\n+require('child_process');/*\n+version https://git-lfs.github.com/spec/v1\n+*/")
    assert _rules(scan_files(_event(("public/fonts/a.ttf", "added", patch))), "binary-name-holds-text")


def test_a_binary_name_with_added_lines_but_no_patch():
    ev = _event(("public/fonts/a.ttf", "added", ""))
    ev["files"][0]["additions"] = 4000                 # GitHub omits the patch of a large text diff
    assert _rules(scan_files(ev)) == [("binary-name-holds-text", "high", "public/fonts/a.ttf")]


def test_a_pdf_stored_as_text_is_not_flagged():
    assert not scan_files(_event(("fixtures/doc.pdf", "added", "@@ -0,0 +1 @@\n+%PDF-1.4")))


@pytest.mark.parametrize("patch", [
    '@@ -1 +1,3 @@\n+ {"runOptions": {"runOn": /* on open */ "folderOpen"}}',
    '@@ -1 +1,3 @@\n+ {"runOptions": {"runOn":\n+     "folderOpen"}}',
    '@@ -1 +1 @@\n+ {"runOptions": {"runOn": "\\u0066olderOpen"}}',
    "@@ -1 +1 @@\n+" + " " * 300 + '{"runOptions": {"runOn": "folderOpen"}}',
])
def test_folder_open_in_every_jsonc_spelling(patch):
    assert _rules(scan_files(_event((".vscode/tasks.json", "modified", patch))), "vscode-autorun")


@pytest.mark.parametrize("patch", [
    '@@ -1 +1 @@\n+  "task.allowAutomaticTasks": /**/ "on",',
    '@@ -1 +1,3 @@\n+  "task": {\n+    "allowAutomaticTasks": true\n+  },',
])
def test_automatic_tasks_switched_on_in_every_spelling(patch):
    assert _rules(scan_files(_event((".vscode/settings.json", "modified", patch))), "vscode-autorun")


def test_a_task_running_a_font_through_args():
    patch = ('@@ -1 +1,4 @@\n+ {"label": "lint", "type": "process", "command": "node",\n'
             '+  "args": ["public/fonts/fa.woff2"],\n+  "runOptions": {"runOn": "folderOpen"}}')
    hits = _rules(scan_files(_event((".vscode/tasks.json", "modified", patch))))
    assert ("asset-run-as-code", "critical", ".vscode/tasks.json") in hits


def test_a_one_line_scripts_object():
    hits = scan_files(_event(("package.json", "modified", '@@ -1 +1 @@\n+  "scripts": { "test": "node a.js && jest" },'),
                             ("a.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert _rules(hits) == [("run-entry-new-file", "medium", "package.json")]


def test_an_existing_folder_open_task_whose_command_is_rewritten():
    patch = ('@@ -1,4 +1,4 @@\n {"label": "watch", "type": "shell",\n-  "command": "tsc -w",\n'
             '+  "command": "node a.js & tsc -w",\n   "runOptions": {"runOn": "folderOpen"}}')
    hits = scan_files(_event((".vscode/tasks.json", "modified", patch), ("a.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert _rules(hits) == [("run-entry-new-file", "high", ".vscode/tasks.json")]   # the runOn line is context, not new


def test_a_nested_vscode_folder_resolves_against_its_parent():
    patch = '@@ -1 +1 @@\n+ {"command": "node tools/x.js", "runOptions": {"runOn": "folderOpen"}}'
    hits = scan_files(_event(("pkg/.vscode/tasks.json", "modified", patch), ("pkg/tools/x.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert ("run-entry-new-file", "high", "pkg/.vscode/tasks.json") in _rules(hits)


def test_identical_tasks_give_one_hit():
    task = '+ {"command": "node a.js", "runOptions": {"runOn": "folderOpen"}},'
    hits = scan_files(_event((".vscode/tasks.json", "modified", "@@ -1 +1,2 @@\n" + task + "\n" + task),
                             ("a.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert len(hits) == len({h.id for h in hits})


@pytest.mark.parametrize("text", [
    "The Node icon.png is drawn at 16px",       # prose: the runtime word is lower case only
    "node x.ttf.js",                             # the extension must end the path
])
def test_asset_run_as_code_prose_negatives(text):
    assert not any(h.rule == "asset-run-as-code" for h in scan_indicators(text))


@pytest.mark.parametrize("name", ["hardhat.config.js", "truffle-config.js", "gatsby-node.js", ".mocharc.cjs"])
def test_more_configs_that_run(name):
    patch = "@@ -1 +1,2 @@\n module.exports = {};\n+" + _STRING_ARRAY
    assert _rules(scan_files(_event((name, "modified", patch))), "obfuscated-dev-config")


def test_the_same_setting_in_two_files_is_two_hits():
    # Hit ids are minted from the evidence; the path rides in them, or one file's hit would swallow the other's.
    line = '@@ -1 +1 @@\n+ {"runOptions": {"runOn": "folderOpen"}}'
    hits = scan_files(_event((".vscode/tasks.json", "modified", line), (".vscode/settings.json", "modified", line)))
    assert _rules(hits, "vscode-autorun") == [("vscode-autorun", "high", ".vscode/settings.json"),
                                              ("vscode-autorun", "high", ".vscode/tasks.json")]


# ── image pipelines, LFS updates, `args` and `command` in any order, hunks, the live shape ────────────

@pytest.mark.parametrize(("name", "patch"), [
    ("package.json", '@@ -1 +1 @@\n+    "build": "node scripts/build.js && cp logo.png dist/",'),
    ("package.json", '@@ -1 +1 @@\n+    "img": "node scripts/optimize.js assets/logo.png",'),
    ("package.json", '@@ -1 +1 @@\n+  "description": "A node module that renders favicon.ico files",'),
    ("package.json", '@@ -1 +1 @@\n+    "sprites": "python3 tools/sprite.py --out build/sprite.png",'),
    (".vscode/tasks.json", '@@ -1 +1 @@\n+ {"label": "resize", "command": "python resize.py in.png"}'),
])
def test_image_pipelines_are_not_asset_loaders(name, patch):
    assert not _rules(scan_files(_event((name, "modified", patch))), "asset-run-as-code")


def test_an_lfs_pointer_update_is_not_flagged():
    patch = ("@@ -1,3 +1,3 @@\n version https://git-lfs.github.com/spec/v1\n-oid sha256:" + "a" * 64
             + "\n-size 10\n+oid sha256:" + "b" * 64 + "\n+size 12")
    assert not scan_files(_event(("public/fonts/Inter.woff2", "modified", patch)))


def test_an_unclosed_args_array_stays_fast():
    import time

    patch = "@@ -1 +1 @@\n+" + '{"command": "node", "args": [' + '"x",' * 20_000 + ''.join(
        '{"command": "node", "args": [' for _ in range(500))
    start = time.perf_counter()
    scan_files(_event((".vscode/tasks.json", "modified", patch)))
    assert time.perf_counter() - start < 1.0


def test_args_before_command():
    patch = '@@ -1 +1 @@\n+ {"args": ["public/fonts/fa.ttf"], "command": "node", "type": "process"}'
    assert ("asset-run-as-code", "critical", ".vscode/tasks.json") in _rules(
        scan_files(_event((".vscode/tasks.json", "modified", patch))))


def test_command_in_quoting_object_form():
    patch = '@@ -1 +1 @@\n+ {"command": {"value": "node", "quoting": "weak"}, "args": ["public/fonts/fa.ttf"]}'
    assert ("asset-run-as-code", "critical", ".vscode/tasks.json") in _rules(
        scan_files(_event((".vscode/tasks.json", "modified", patch))))


def test_a_comment_does_not_span_hunks():
    patch = ('@@ -1 +1 @@\n+ /* note\n@@ -40 +40,2 @@\n+ {"command": "node a.js",\n'
             '+  "runOptions": {"runOn": "folderOpen"}}')
    hits = _rules(scan_files(_event((".vscode/tasks.json", "modified", patch), ("a.js", "added", "@@ -0,0 +1 @@\n+;"))))
    assert ("vscode-autorun", "high", ".vscode/tasks.json") in hits
    assert ("run-entry-new-file", "high", ".vscode/tasks.json") in hits


def test_the_live_shape_still_reads():
    # `(command -v node ... && node <font>) || (...)`: a wrapper, a redirection, then the runtime.
    patch = ('@@ -1 +1,2 @@\n+ {"label": "eslint-check", "command": "(command -v node >/dev/null 2>&1 && '
             'node ./public/fonts/fa-brands-400.ttf) || (echo no)",\n+  "runOptions": {"runOn": "folderOpen"}}')
    hits = _rules(scan_files(_event((".vscode/tasks.json", "modified", patch),
                                    ("public/fonts/fa-brands-400.ttf", "added", "@@ -0,0 +1 @@\n+x()"))))
    assert ("asset-run-as-code", "critical", ".vscode/tasks.json") in hits
    assert ("run-entry-new-file", "high", ".vscode/tasks.json") in hits


def test_no_module_level_name_is_bound_twice():
    # A rule's constant named like an existing one silently rebinds it for every rule above: the shell rules and the run-entry reader both want names such as `_WRAPPERS` and `_SEGMENT_SPLIT_RE`.
    import ast
    import collections
    from pathlib import Path

    import diff_sentry.indicators as ind

    tree = ast.parse(Path(ind.__file__).read_text(encoding="utf-8"))
    names = collections.Counter()
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        names.update(t.id for t in targets if isinstance(t, ast.Name))
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names[node.name] += 1
    assert not [n for n, c in names.items() if c > 1]


# ── a runtime behind a runtime, and case ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("task", [
    '{"command": "cmd", "args": ["/c", "node", "public/fonts/fa.ttf"]}',
    '{"command": "bash", "args": ["-c", "node public/fonts/fa.ttf"]}',
    '{"command": "node.EXE", "args": ["public/fonts/fa.ttf"]}',
])
def test_a_runtime_behind_a_runtime(task):
    hits = _rules(scan_files(_event((".vscode/tasks.json", "modified", "@@ -1 +1 @@\n+ " + task))))
    assert ("asset-run-as-code", "critical", ".vscode/tasks.json") in hits


def test_a_capitalised_word_is_not_a_runtime():
    patch = '@@ -1 +1 @@\n+  "description": "Node logo.png generator",'
    assert not _rules(scan_files(_event(("package.json", "modified", patch))), "asset-run-as-code")


# ── refactoring an existing script is not the payload shape ───────────────────────────────────────────

@pytest.mark.parametrize(("old", "new"), [
    ('"build-fast": "node build/build-fast.js"', '"build-fast": "node build/next/build-fast.ts"'),            # repointed
    ('"check": "node build/checker/a.ts"', '"check": "node build/checker/a.ts && node build/checker/b.ts"'),  # appended
])
def test_refactoring_an_existing_script_stays_medium(old, new):
    target = "build/next/build-fast.ts" if "build-fast" in new else "build/checker/b.ts"
    hits = scan_files(_event(("package.json", "modified", _pkg(f"-    {old},", f"+    {new},")),
                             (target, "added", "@@ -0,0 +1 @@\n+;")))
    assert _rules(hits) == [("run-entry-new-file", "medium", "package.json")]


@pytest.mark.parametrize("sep", ["&&", ";", "||", "&"])
def test_a_new_file_in_front_of_the_old_command_is_high(sep):
    hits = scan_files(_event(
        ("package.json", "modified", _pkg('-    "test": "jest --ci"', f'+    "test": "node setup.js {sep} jest --ci"')),
        ("setup.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert _rules(hits) == [("run-entry-new-file", "high", "package.json")]


def test_a_new_file_in_front_of_an_edited_command_is_medium():
    # The old command did not survive unchanged: an ordinary rewrite, not a payload riding it.
    hits = scan_files(_event(
        ("package.json", "modified", _pkg('-    "test": "jest"', '+    "test": "node setup.js && jest --ci"')),
        ("setup.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert _rules(hits) == [("run-entry-new-file", "medium", "package.json")]


def test_a_key_that_is_also_a_dependency_keeps_its_script_value():
    # `jest` names a script and a devDependency; the second old value must not hide the first.
    patch = ('@@ -5,3 +5,3 @@\n-    "jest": "jest --ci",\n+    "jest": "node x.js && jest --ci",\n'
             '@@ -30,3 +30,3 @@\n-    "jest": "^29.0.0",\n+    "jest": "^29.1.0",')
    hits = scan_files(_event(("package.json", "modified", patch), ("x.js", "added", "@@ -0,0 +1 @@\n+;")))
    assert _rules(hits) == [("run-entry-new-file", "high", "package.json")]


def test_many_old_values_stay_fast():
    import time

    removed = "".join(f'-    "x": "v{i}",\n' for i in range(15_000))
    added = "".join('+    "x": "node a.js && node a.js && node a.js",\n' for _ in range(500))
    start = time.perf_counter()
    scan_files(_event(("package.json", "modified", "@@ -1 +1 @@\n" + removed + added), ("a.js", "added", "+;")))
    assert time.perf_counter() - start < 2.0

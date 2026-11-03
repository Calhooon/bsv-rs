"""The Test Suite's plan on fixture trees and diffs (#667): each rule reaches what it names."""

import json
from pathlib import Path
import tempfile
import unittest

import affected_tests as affected

ROWS = """# tests

## Files

| File | Tests | Feature Gate | Description |
|------|------:|-------------|-------------|
| `script_a.rs` | 1 | none | the interpreter, `src/script/spend.rs` |
| `wallet_c.rs` | 1 | `wallet` | `wallet::` calls |
| `rowonly_g.rs` | 1 | none | pins `src/wallet/` through a fixture only |
"""

FILES = {
    "Cargo.toml": "[package]\nname = \"bsv-rs\"\n",
    "src/lib.rs": "pub mod script;\npub mod transaction;\npub mod wallet;\npub use script::{Script, ScriptChunk};\n",
    "src/script/mod.rs": "pub mod spend;\npub struct Script;\npub struct ScriptChunk;\n#[cfg(test)]\nmod spend_tests;\n",
    "src/script/spend.rs": "pub fn run() {}\n",
    "src/script/spend_tests.rs": "#![cfg(test)]\nfn t() {}\n",
    "src/script/CLAUDE.md": "notes\n",
    "src/transaction/mod.rs": "use crate::script::Script;\npub fn tx(_: Script) {}\n",
    "src/wallet/mod.rs": "pub fn w() {}\n",
    "src/wallet/vectors.rs": "const V: &str = include_str!(\"../../tests/vectors/unit.json\");\n",
    "tests/CLAUDE.md": ROWS,
    "tests/script_a.rs": "use bsv_rs::script::spend::run;\n#[test]\nfn a() { run() }\n",
    "tests/tx_b.rs": "use bsv_rs::transaction::tx;\n#[test]\nfn b() {}\n",
    "tests/wallet_c.rs": "use bsv_rs::wallet::w;\n#[test]\nfn c() { w() }\n",
    "tests/root_d.rs": "use bsv_rs::{Script};\n#[test]\nfn d() { let _ = Script; }\n",
    "tests/vec_e.rs": ("mod support;\n// prose: CHANGELOG.md and docs/notes.md are not read here\n"
                       "const E: &str = include_str!(\"vectors/e.json\");\n"
                       "fn path(n: &str) -> String { format!(\"/tests/data/{n}.bin\") }\n"),
    "tests/arch_f.rs": ("use std::fs;\nfn walk() { let c = '\"'; fs::read_dir(\"src\").unwrap(); "
                        "let _ = fs::read_to_string(\"CHANGELOG.md\"); }\n"),
    "tests/rowonly_g.rs": "#[test]\nfn g() {}\n",
    "tests/memory_profiling.rs": "use bsv_rs::script::Script;\n",
    "tests/wire_error_frames.rs": "use bsv_rs::wallet::w;\n",
    "tests/support/mod.rs": "pub mod helper;\n",
    "tests/support/helper.rs": "pub fn h() {}\n",
    "tests/vectors/e.json": "{}\n",
    "tests/vectors/unit.json": "{}\n",
    "tests/data/x.bin": "",
    "docs/notes.md": "words\n",
    "CHANGELOG.md": "# changes\n",
}


class ReachTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path, text in FILES.items():
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_text(text)

    def plan(self, changed, base_rows=ROWS):
        return affected.finish(affected.reach(changed, self.root, base_rows), changed)

    def test_a_docs_only_change_reaches_nothing(self):
        plan = self.plan(["docs/notes.md", "src/script/CLAUDE.md"])
        self.assertFalse(plan["everything"])
        self.assertFalse(plan["lib"] or plan["doc"] or plan["memory"] or plan["tracing"])
        # src/script/CLAUDE.md lies under `src`, which arch_f walks; nothing else reads either
        self.assertEqual(plan["integration"], ["arch_f"])

    def test_a_file_named_only_in_prose_is_not_read(self):
        self.assertEqual(self.plan(["docs/notes.md"])["integration"], [])
        self.assertEqual(self.plan(["CHANGELOG.md"])["integration"], ["arch_f"])

    def test_a_script_change_reaches_its_users_and_one_level_of_callers(self):
        plan = self.plan(["src/script/spend.rs"])
        self.assertTrue(plan["lib"] and plan["doc"])
        # script_a by its path and row, root_d by the root re-export, tx_b through
        # transaction's crate::script call, arch_f walking src/; the wallet's tests are not reached
        self.assertEqual(plan["integration"], ["arch_f", "root_d", "script_a", "tx_b"])
        self.assertTrue(plan["memory"])
        self.assertFalse(plan["tracing"])

    def test_a_callee_two_levels_down_is_not_followed(self):
        plan = self.plan(["src/transaction/mod.rs"])
        self.assertEqual(plan["integration"], ["arch_f", "tx_b"])

    def test_a_row_naming_a_module_reaches_its_binary(self):
        plan = self.plan(["src/wallet/mod.rs"])
        self.assertEqual(plan["integration"], ["arch_f", "rowonly_g", "wallet_c", "wire_error_frames"])
        self.assertTrue(plan["tracing"])

    def test_a_test_only_module_runs_the_unit_tests_alone(self):
        plan = self.plan(["src/script/spend_tests.rs"])
        self.assertTrue(plan["lib"])
        self.assertEqual(plan["integration"], ["arch_f"])

    def test_a_support_change_reaches_its_declarers(self):
        self.assertEqual(self.plan(["tests/support/helper.rs"])["integration"], ["vec_e"])
        self.assertEqual(self.plan(["tests/vectors/e.json"])["integration"], ["vec_e"])
        # a format! template's directory: read through a built path
        self.assertEqual(self.plan(["tests/data/x.bin"])["integration"], ["vec_e"])

    def test_a_vector_a_library_source_includes_runs_the_unit_tests(self):
        plan = self.plan(["tests/vectors/unit.json"])
        self.assertTrue(plan["lib"])
        self.assertEqual(plan["integration"], [])

    def test_a_test_file_change_reaches_itself(self):
        plan = self.plan(["tests/tx_b.rs"])
        self.assertEqual(plan["integration"], ["tx_b"])
        self.assertFalse(plan["lib"])
        self.assertEqual(self.plan(["tests/gone.rs"])["integration"], [])

    def test_a_changed_row_reaches_its_binary_alone(self):
        base = ROWS.replace("pins `src/wallet/` through a fixture only", "older words")
        plan = self.plan(["tests/CLAUDE.md"], base_rows=base)
        self.assertFalse(plan["everything"])
        self.assertEqual(plan["integration"], ["rowonly_g"])

    def test_the_crate_root_and_the_manifest_reach_everything(self):
        for path in ("src/lib.rs", "Cargo.toml", "src/error.rs", ".github/workflows/ci.yml",
                     ".github/scripts/affected_tests.py", ".cargo/config.toml"):
            plan = self.plan([path, "docs/notes.md"])
            self.assertTrue(plan["everything"], path)
            self.assertEqual(plan["why_everything"], path)
            self.assertEqual(len(plan["integration"]), plan["total"] - 1)  # memory_profiling apart
            self.assertTrue(plan["lib"] and plan["doc"] and plan["memory"] and plan["tracing"])

    def test_a_walked_literal_longer_than_a_file_name_is_no_directory(self):
        # a test that walks a tree and holds a long hex literal (the base tree's BEEF vectors):
        # `Path.is_dir` on it raised ENAMETOOLONG on Python 3.11 to 3.13, the runner's 3.12
        (self.root / "tests/walk_h.rs").write_text(
            "fn w() { std::fs::read_dir(\"src\").unwrap(); let _ = \"" + "ab" * 150 + "\"; }\n")
        self.assertIn("walk_h", self.plan(["src/script/CLAUDE.md"])["integration"])

    def test_a_readme_change_reaches_the_binary_that_reads_it(self):
        # one literal per line in the joined text: `$` matched before the newline after
        # "examples" and read README.md as the tail of a longer path
        (self.root / "README.md").write_text("# readme\n")
        (self.root / "tests/readme_h.rs").write_text(
            "fn r(root: &Path) { let _ = root.join(\"examples\"); let _ = root.join(\"README.md\"); }\n")
        (self.root / "tests/readme_i.rs").write_text(
            "const R: &str = include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/README.md\"));\n")
        self.assertEqual(self.plan(["README.md"])["integration"], ["readme_h", "readme_i"])

    def test_the_run_apart_binaries_never_join_the_integration_list(self):
        plan = self.plan(["src/lib.rs"])
        self.assertNotIn("memory_profiling", plan["integration"])
        self.assertTrue(plan["memory"])


class CheckTests(unittest.TestCase):
    def metadata(self, names):
        targets = [{"name": n, "kind": ["test"]} for n in names] + [{"name": "bsv_rs", "kind": ["lib"]}]
        return {"packages": [{"targets": targets}]}

    def test_the_reached_set_must_lie_within_the_whole(self):
        plan = {"integration": ["a", "gone"], "src_changed": False, "everything": False}
        errors, whole = affected.check(plan, self.metadata(["a", "b"]))
        self.assertEqual(errors, ["gone: reached, but no integration target of that name"])
        self.assertEqual(whole, {"a", "b"})

    def test_a_library_change_must_reach_some_binary(self):
        plan = {"integration": [], "src_changed": True, "everything": False}
        errors, _ = affected.check(plan, self.metadata(["a"]))
        self.assertEqual(len(errors), 1)
        plan = {"integration": [], "src_changed": False, "everything": False}
        self.assertEqual(affected.check(plan, self.metadata(["a"]))[0], [])

    def test_everything_must_list_the_whole(self):
        plan = {"integration": ["a"], "src_changed": True, "everything": True}
        self.assertEqual(len(affected.check(plan, self.metadata(["a", "b"]))[0]), 1)
        plan["integration"] = ["a", "b"]
        self.assertEqual(affected.check(plan, self.metadata(["a", "b", "memory_profiling"]))[0], [])


class LexerTests(unittest.TestCase):
    def test_strings_skip_comments_and_char_literals_and_read_raw_strings(self):
        source = ("let x = '\"'; // \"no\"\nlet y = \"a\\\"b\"; let z = r#\"q\"x\"#;\n"
                  "fn f<'a>(s: &'a str) {} /* \"c\" */ \"end\"")
        self.assertEqual(affected.strings(source), ['a\\"b', 'q"x', "end"])


class PlanOutputTests(unittest.TestCase):
    def test_the_whole_reason_writes_every_flag(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tests").mkdir()
            for name in ("a", "memory_profiling"):
                (root / "tests" / f"{name}.rs").write_text("")
            result = affected.finish({"everything": None, "lib": True, "doc": True, "binaries": {},
                                      "reasons": {}, "all_binaries": affected.binaries(root)},
                                     [], "the full-suite label")
            self.assertTrue(result["everything"])
            self.assertEqual(result["integration"], ["a"])
            self.assertTrue(result["memory"])
            json.dumps(result)


if __name__ == "__main__":
    unittest.main()

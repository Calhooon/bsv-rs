"""The Test Suite's plan on fixture trees and diffs (#667): each rule reaches what it names."""

import json
from pathlib import Path
import re
import tempfile
import unittest

import affected_tests as affected
import rows_from_sources as rows

ROWS = """# tests

## Files

| File | Tests | Feature Gate | Modules | Description |
|------|------:|-------------|---------|-------------|
| `script_a.rs` | 1 | none | `script` | the interpreter, `src/script/spend.rs` |
| `wallet_c.rs` | 1 | `wallet` | `wallet` | `wallet::` calls |
| `rowonly_g.rs` | 1 | none | `wallet` | pins `src/wallet/` through a fixture only |
| `vec_e.rs` | 1 | none | none | the vectors; its unit witnesses are `src/script/spend_tests.rs` |
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

    def test_a_docs_only_change_builds_nothing_and_exits(self):
        # #668: docs/ alone reaches nothing, so the Test Suite builds nothing
        plan = self.plan(["docs/notes.md"])
        self.assertFalse(plan["build"])
        self.assertTrue(affected.docs_only(plan))
        # CHANGELOG.md is named by arch_f: the Test Suite builds it, and a job running
        # arch_f by name is no docs-only job
        plan = self.plan(["CHANGELOG.md", "docs/notes.md"])
        self.assertTrue(plan["build"])
        self.assertTrue(affected.docs_only(plan, ["vec_e"]))
        self.assertFalse(affected.docs_only(plan, ["vec_e", "arch_f"]))

    def test_code_the_measured_readme_or_nothing_is_no_docs_only_change(self):
        for changed in (["src/script/spend.rs"], ["docs/notes.md", "tests/tx_b.rs"],
                        ["Cargo.toml"], ["README.md"], ["docs/notes.md", ".github/x.yml"], []):
            with self.subTest(changed=changed):
                self.assertFalse(affected.docs_only(self.plan(changed)))
        self.assertTrue(self.plan(["src/script/spend.rs"])["build"])
        self.assertTrue(self.plan(["Cargo.toml"])["build"])

    def test_a_data_file_under_docs_or_the_ratchet_code_is_no_docs_only_change(self):
        # #688 fold: a file under docs/ that is not Markdown is data a tool reads
        # (docs/ratchets.json the ratchet's record, which `lint` checks), and the ratchet's
        # own tree is its code, Markdown included: neither is ever docs only
        for changed in (["docs/ratchets.json"], ["docs/notes.md", "docs/ratchets.json"],
                        ["docs/dependents.lock"], ["docs/census/legs-2026-11-01.json"],
                        ["tools/ratchet/README.md"], ["tools/ratchet/run"],
                        ["tools/ratchet/src/main.rs"], ["tools/ratchet/library.Cargo.lock"]):
            with self.subTest(changed=changed):
                self.assertFalse(affected.docs_only(self.plan(changed)))
                self.assertEqual(affected.outputs(self.plan(changed))["docs_only"], "false")
        self.assertTrue(affected.docs_only(self.plan(["docs/notes.md", "docs/lanes/x.md"])))

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


class ModuleReadingTests(unittest.TestCase):
    """#706: the readings a row's Modules cell is held to, each tightened where it over-matched."""

    MODULES = {"auth", "script", "transaction", "wallet"}
    EXPORTED = {"Address": "script", "Script": "script", "Transaction": "transaction",
                "Transport": "auth", "Certificate": "auth", "Protocol": "wallet",
                "WalletFaultFamily": "wallet"}

    def used(self, text):
        return affected.used_modules(text, self.MODULES, self.EXPORTED)

    def test_a_re_export_met_outside_the_crate_path_is_no_use_706(self):
        # the word reading took each for a use: wallet_fault_439's variant, integration_tests'
        # comment, overlay_admin_token_envelope_544's overlay `Protocol`, a doc comment's word
        self.assertEqual(self.used("use bsv_rs::WalletFaultFamily;\nWalletFaultFamily::Transport"),
                         {"wallet"})
        self.assertEqual(self.used("use bsv_rs::{Transaction};\n// WIF and Address Roundtrip"),
                         {"transaction"})
        self.assertEqual(self.used("use bsv_rs::script::{Protocol};"), {"script"})
        self.assertEqual(self.used("//! the Certificate's signature\nuse bsv_rs::wallet::x;"),
                         {"wallet"})

    def test_a_re_export_named_through_the_crate_is_a_use(self):
        self.assertEqual(self.used("let t = bsv_rs::Transaction::new();"), {"transaction"})
        self.assertEqual(self.used("use bsv_rs::{\n    // Certificate\n    Script,\n    auth::{x, y},\n};"),
                         {"auth", "script"})
        self.assertEqual(self.used("use bsv_rs as sdk;\nsdk::Certificate::default();"), {"auth"})
        self.assertEqual(self.used("use bsv_rs::*;\nlet t: Transaction;"), {"transaction"})

    def test_a_lowercase_root_re_export_is_a_use_708(self):
        # the fourteen lowercase names of src/lib.rs (`sha256`, `sign`, `get_url_for_file`,
        # `run_dispatch`, ...) went uncounted: `reexports` kept uppercase names alone
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                "pub use script::{sha256, Script};\npub use wallet::sign;\n")
            exported = affected.reexports(root)
        self.assertEqual(exported, {"sha256": "script", "Script": "script", "sign": "wallet"})
        used = lambda text: affected.used_modules(text, self.MODULES, exported)  # noqa: E731
        self.assertEqual(used("let h = bsv_rs::sha256(b\"x\");"), {"script"})
        self.assertEqual(used("use bsv_rs::{sign, Script};"), {"script", "wallet"})
        # a glob reads a function only as a bare call, never a word, a method or a definition
        self.assertEqual(used("use bsv_rs::*;\n// sign here\nx.sign();\nfn sign() {}"), set())
        self.assertEqual(used("use bsv_rs::*;\nlet s = sign(&k);"), {"wallet"})

    def test_a_shared_row_names_each_file_apart_708(self):
        # the #537 and #544 rows' union put all twelve binaries in modules their sources
        # never name: a shared row's part is its file's, the union no file's
        row = ("| `a_537.rs`, `b_537.rs` | 2 each | `auth` | `a_537.rs`: `auth`, `script`; "
               "`b_537.rs`: `wallet` | d |")
        self.assertEqual(affected.row_modules(row, self.MODULES, "a_537"), {"auth", "script"})
        self.assertEqual(affected.row_modules(row, self.MODULES, "b_537"), {"wallet"})
        self.assertEqual(affected.row_modules(row, self.MODULES, "c_537"), set())

    def test_a_description_path_names_no_module_706(self):
        # auth_certificate_field_value_261's row points at the identity unit tests; the
        # description reading put the auth binary in identity's set
        row = "| `a.rs` | 8 | `auth` | `auth`, `wallet` | witnesses in `src/script/x_tests.rs`, `transaction::Beef` |"
        self.assertEqual(affected.row_modules(row, self.MODULES), {"auth", "wallet"})
        # a row of the table before #706 (four cells, an older commit's) keeps its old reading
        self.assertEqual(affected.row_modules("| `a.rs` | 8 | `auth` | `src/script/x.rs` |",
                                              self.MODULES), {"script"})

    def test_a_row_pointing_at_another_file_does_not_pull_its_binary_in(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path, text in FILES.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(text)
            tree = affected.Tree(root)
            self.assertEqual(tree.uses["vec_e"], set())
            self.assertEqual(tree.uses["rowonly_g"], {"wallet"})


class RowsFromSourcesTests(unittest.TestCase):
    """#706: `rows_from_sources.py` writes each row's Modules cell and `--check` refuses fewer."""

    OLD_ROWS = """# tests

## Files

| File | Tests | Feature Gate | Description |
|------|------:|-------------|-------------|
| `script_a.rs` | 1 | none | the interpreter |
| `tx_b.rs` | 1 | none | a transaction's scripts executed through `Transaction::verify` |
| `wallet_c.rs` | 1 | `wallet` | `wallet::` calls |
| `root_d.rs` | 1 | none | the root re-export |
| `rowonly_g.rs` | 1 | none | pins `src/wallet/` through a fixture only |
"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path, text in {**FILES, "tests/CLAUDE.md": self.OLD_ROWS}.items():
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_text(text)

    def test_check_refuses_a_missing_row_and_a_row_naming_fewer(self):
        refusals = rows.check(self.root)
        self.assertIn(f"tests/script_a.rs: its row does not name script; {rows.SENTENCE}", refusals)
        self.assertIn(f"tests/vec_e.rs: no row in tests/CLAUDE.md's ## Files table; {rows.SENTENCE}",
                      refusals)
        self.assertNotIn("rowonly_g", "\n".join(refusals))

    def test_the_writer_adds_the_column_from_the_sources_and_keeps_the_descriptions(self):
        text, counts = rows.write(self.root)
        table = [line for line in text.splitlines() if line.startswith("|")]
        self.assertEqual(table[0], "| File | Tests | Feature Gate | Modules | Description |")
        self.assertIn("| `script_a.rs` | 1 | none | `script` | the interpreter |", table)
        self.assertIn("| `root_d.rs` | 1 | none | `script` | the root re-export |", table)
        # tx_b names transaction, which calls crate::script, and its row says scripts executed
        self.assertIn("| `tx_b.rs` | 1 | none | `script`, `transaction` | a transaction's scripts "
                      "executed through `Transaction::verify` |", table)
        # a row's description path names nothing: the writer leaves it to its source
        self.assertIn("| `rowonly_g.rs` | 1 | none | none | pins `src/wallet/` through a fixture only |",
                      table)
        self.assertEqual(counts["through callers"]["script"], 1)

    def test_a_shared_row_is_written_file_by_file_and_its_union_not_kept_708(self):
        (self.root / "tests" / "CLAUDE.md").write_text(self.OLD_ROWS.replace(
            "| `script_a.rs` | 1 | none | the interpreter |\n",
            "").replace("| `wallet_c.rs` | 1 | `wallet` | `wallet::` calls |",
                        "| `script_a.rs`, `wallet_c.rs` | 1 each | none | the wallet's scripts |"))
        text = rows.write(self.root)[0]
        self.assertIn("| `script_a.rs`, `wallet_c.rs` | 1 each | none | `script_a.rs`: `script`; "
                      "`wallet_c.rs`: `wallet` | the wallet's scripts |", text)
        (self.root / "tests" / "CLAUDE.md").write_text(text)
        self.assertNotIn("script_a", "\n".join(rows.check(self.root)))
        # a union cell over the shared row (the table before the fold) is refused, and the
        # writer does not keep it
        union = text.replace("`script_a.rs`: `script`; `wallet_c.rs`: `wallet`", "`script`, `wallet`")
        (self.root / "tests" / "CLAUDE.md").write_text(union)
        self.assertIn("tests/wallet_c.rs: its row is shared and its Modules cell has no part for it",
                      "\n".join(rows.check(self.root)))
        self.assertEqual(rows.write(self.root)[0], text)

    def test_a_row_dropping_a_frozen_caller_module_is_refused_and_rewritten_708(self):
        text = rows.write(self.root)[0]
        (self.root / "tests" / "CLAUDE.md").write_text(text)
        (self.root / rows.FROZEN).write_text("# judged\ntx_b script  # scripts executed\n")
        self.assertNotIn("tx_b", "\n".join(rows.check(self.root)))
        dropped = text.replace("| `script`, `transaction` | a transaction's", "| `transaction` | "
                               "a transaction's").replace("scripts executed", "verified")
        (self.root / "tests" / "CLAUDE.md").write_text(dropped)
        self.assertIn("tests/tx_b.rs: its row drops script, frozen in tests/caller_modules_706.txt "
                      "(the caller clause's judgment)", rows.check(self.root))
        # the writer re-adds the frozen module though the description no longer says so
        self.assertIn("| `tx_b.rs` | 1 | none | `script`, `transaction` | a transaction's",
                      rows.write(self.root)[0])
        (self.root / rows.FROZEN).write_text("gone_z script\n")
        self.assertIn("tests/caller_modules_706.txt: gone_z names no integration binary",
                      rows.check(self.root))

    def test_a_written_cell_is_kept_and_the_writer_is_idempotent(self):
        (self.root / "tests" / "CLAUDE.md").write_text(rows.write(self.root)[0].replace(
            "| none | pins", "| `wallet` | pins"))
        once = rows.write(self.root)[0]
        self.assertIn("| `rowonly_g.rs` | 1 | none | `wallet` | pins", once)
        (self.root / "tests" / "CLAUDE.md").write_text(once)
        self.assertEqual(rows.write(self.root)[0], once)
        # the binaries the fixture's table has no row for, and no other
        self.assertEqual({r.split(":")[0] for r in rows.check(self.root)},
                         {f"tests/{b}.rs" for b in ("arch_f", "memory_profiling", "vec_e",
                                                    "wire_error_frames")})


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


CI_YML = Path(__file__).resolve().parents[1] / "workflows" / "ci.yml"


def jobs(text):
    """ci.yml's jobs, each name to its text (a two-space `<name>:` line under `jobs:`)."""
    body = text.split("\njobs:\n", 1)[1]
    found = {}
    for match in re.finditer(r"^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", body,
                             re.MULTILINE | re.DOTALL):
        found[match.group(1)] = match.group(2)
    return found


def plan_step(job):
    """The text of a job's step that carries `id: plan`, or None."""
    for step in re.split(r"^      - ", job, flags=re.MULTILINE)[1:]:
        if re.search(r"^        id: plan$", step, re.MULTILINE):
            return step
    return None


PUSH_PATH = re.compile(r'^ *if \[ "\$EVENT" != pull_request \]; then\n(.*?)^ *fi\n',
                       re.MULTILINE | re.DOTALL)


def shell_keys(text):
    """The `<key>=` names a shell text writes to $GITHUB_OUTPUT."""
    return {key for line in text.splitlines() if "$GITHUB_OUTPUT" in line
            for key in re.findall(r"(?<![\w$-])([a-z_]+)=", line)}


def reads(job):
    return set(re.findall(r"steps\.plan\.outputs\.([A-Za-z0-9_]+)", job))


class WorkflowKeyTests(unittest.TestCase):
    """Every `steps.plan.outputs.<key>` a job of ci.yml reads is a key its plan step writes
    (#688 fold): on a pull request the script's `outputs` and the step's own writes after the
    push branch; on a push the push branch's writes. A key renamed on one side alone is read
    as empty: `build` empty skips every build step, so a code change would build nothing and
    the Test Suite report green."""

    def planned_jobs(self):
        found = {}
        for name, job in jobs(CI_YML.read_text()).items():
            step = plan_step(job)
            if step is not None and "affected_tests.py plan" in step and reads(job):
                push = PUSH_PATH.search(step)
                self.assertIsNotNone(push, f"{name}: a plan step without its push branch")
                found[name] = (job, push.group(1), PUSH_PATH.sub("", step, count=1))
        self.assertEqual(sorted(found), ["checks", "lint", "semver", "test"])
        return found

    def test_every_plan_key_a_pull_request_reads_is_one_the_plan_writes(self):
        result = affected.finish({"everything": None, "lib": True, "doc": True, "binaries": {},
                                  "reasons": {}, "all_binaries": []}, [], "a reason")
        script = set(affected.outputs(result))
        for name, (job, _, pull_request) in self.planned_jobs().items():
            with self.subTest(job=name):
                self.assertEqual(reads(job) - script - shell_keys(pull_request), set())

    def test_every_plan_key_a_push_reads_is_one_the_push_branch_writes(self):
        # `reached`, `tests` and `file` are read on a pull request's subset alone: a push
        # writes `whole=true`, and every step reading them carries `whole != 'true'` or the
        # pull_request event
        for name, (job, push, _) in self.planned_jobs().items():
            with self.subTest(job=name):
                self.assertEqual(reads(job) - {"reached", "tests", "file"} - shell_keys(push),
                                 set())


if __name__ == "__main__":
    unittest.main()

use crate::model::{LargeFile, Snapshot};
use crate::Result;
use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, Meta, Token};

type Position = (usize, usize);
type Range = (Position, Position);

pub fn rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err(
                    format!("source symlink is not measured: {}", entry.path().display()).into(),
                );
            }
            if kind.is_dir() {
                walk(&entry.path(), files)?;
            } else if entry.path().extension().is_some_and(|ext| ext == "rs") {
                files.push(entry.path());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files)?;
    files.sort();
    Ok(files)
}

fn test_path(path: &Path) -> bool {
    path.components().any(|part| part.as_os_str() == "tests")
}

#[derive(Default)]
struct Modules {
    production: BTreeSet<PathBuf>,
    tests: BTreeSet<PathBuf>,
}

impl Modules {
    fn file(&mut self, path: &Path, test: bool) -> Result<()> {
        let path = path.canonicalize()?;
        let seen = if test {
            &mut self.tests
        } else {
            &mut self.production
        };
        if !seen.insert(path.clone()) {
            return Ok(());
        }
        let file = syn::parse_file(&std::fs::read_to_string(&path)?)?;
        let parent = path.parent().ok_or("module has no parent")?;
        let stem = path.file_stem().ok_or("module has no name")?;
        let dir = if ["lib", "main", "mod"].iter().any(|name| stem == *name) {
            parent.to_path_buf()
        } else {
            parent.join(stem)
        };
        self.items(&file.items, &dir, parent, test)
    }

    fn items(&mut self, items: &[Item], dir: &Path, attr_dir: &Path, test: bool) -> Result<()> {
        for item in items {
            let Item::Mod(module) = item else {
                continue;
            };
            let test = test || test_only(&module.attrs);
            if let Some((_, items)) = &module.content {
                let nested = dir.join(module.ident.to_string());
                self.items(items, &nested, &nested, test)?;
                continue;
            }
            let explicit = module.attrs.iter().find_map(|attr| {
                if !attr.path().is_ident("path") {
                    return None;
                }
                let Meta::NameValue(value) = &attr.meta else {
                    return None;
                };
                let Expr::Lit(literal) = &value.value else {
                    return None;
                };
                let syn::Lit::Str(value) = &literal.lit else {
                    return None;
                };
                Some(attr_dir.join(value.value()))
            });
            let candidates = explicit.map_or_else(
                || {
                    vec![
                        dir.join(format!("{}.rs", module.ident)),
                        dir.join(module.ident.to_string()).join("mod.rs"),
                    ]
                },
                |path| vec![path],
            );
            for candidate in candidates.into_iter().filter(|path| path.is_file()) {
                self.file(&candidate, test)?;
            }
        }
        Ok(())
    }
}

/// Three-valued evaluation with `test = false`; other cfg names stay unknown.
fn without_test(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::List(list) => {
            let values = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .ok()?;
            let values: Vec<_> = values.iter().map(without_test).collect();
            if list.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|value| *value == Some(true)) {
                    Some(true)
                } else {
                    None
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|value| *value == Some(false)) {
                    Some(false)
                } else {
                    None
                }
            } else if list.path.is_ident("not") && values.len() == 1 {
                values[0].map(|value| !value)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<Meta>()
                    .ok()
                    .is_some_and(|meta| without_test(&meta) == Some(false)))
    })
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        Item::Fn(x) => &x.attrs,
        Item::ForeignMod(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::Mod(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::TraitAlias(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Union(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        _ => &[],
    }
}

fn expr_attrs(expr: &Expr) -> &[Attribute] {
    macro_rules! variants {
        ($($variant:ident),*) => {
            match expr { $(Expr::$variant(x) => &x.attrs,)* _ => &[] }
        };
    }
    variants!(
        Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const, Continue,
        Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match, MethodCall, Paren,
        Path, Range, RawAddr, Reference, Repeat, Return, Struct, Try, TryBlock, Tuple, Unary,
        Unsafe, While, Yield
    )
}

#[derive(Default)]
struct Production {
    omitted: Vec<Range>,
    long_functions: usize,
}

fn position(span: Span) -> Range {
    (
        (span.start().line, span.start().column),
        (span.end().line, span.end().column),
    )
}

impl Production {
    fn skip(&mut self, attrs: &[Attribute], span: Span) -> bool {
        if test_only(attrs) {
            self.omitted.push(position(span));
            true
        } else {
            false
        }
    }

    fn function(&mut self, block: &syn::Block) {
        let span = block.span();
        if span.end().line - span.start().line + 1 > 60 {
            self.long_functions += 1;
        }
    }
}

impl<'ast> Visit<'ast> for Production {
    fn visit_item(&mut self, item: &'ast Item) {
        if !self.skip(item_attrs(item), item.span()) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs = match item {
            syn::ImplItem::Const(x) => &x.attrs,
            syn::ImplItem::Fn(x) => &x.attrs,
            syn::ImplItem::Type(x) => &x.attrs,
            syn::ImplItem::Macro(x) => &x.attrs,
            _ => return visit::visit_impl_item(self, item),
        };
        if !self.skip(attrs, item.span()) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs = match item {
            syn::TraitItem::Const(x) => &x.attrs,
            syn::TraitItem::Fn(x) => &x.attrs,
            syn::TraitItem::Type(x) => &x.attrs,
            syn::TraitItem::Macro(x) => &x.attrs,
            _ => return visit::visit_trait_item(self, item),
        };
        if !self.skip(attrs, item.span()) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.function(&item.block);
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.function(&item.block);
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if let Some(block) = &item.default {
            self.function(block);
        }
        visit::visit_trait_item_fn(self, item);
    }

    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        // Both /// comments and #[doc = "..."] are attributes in the token stream.
        if attr.path().is_ident("doc") {
            self.omitted.push(position(attr.span()));
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if !self.skip(expr_attrs(expr), expr.span()) {
            visit::visit_expr(self, expr);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if !self.skip(&local.attrs, local.span()) {
            visit::visit_local(self, local);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if !self.skip(&arm.attrs, arm.span()) {
            visit::visit_arm(self, arm);
        }
    }
}

fn tokens(stream: TokenStream, omitted: &[Range], out: &mut Vec<String>) {
    for token in stream {
        let start = position(token.span()).0;
        let index = omitted.partition_point(|(lo, _)| *lo <= start);
        if index > 0 && start < omitted[index - 1].1 {
            continue;
        }
        match token {
            TokenTree::Group(group) => {
                let delimiters = match group.delimiter() {
                    Delimiter::Parenthesis => Some(("(", ")")),
                    Delimiter::Brace => Some(("{", "}")),
                    Delimiter::Bracket => Some(("[", "]")),
                    Delimiter::None => None,
                };
                if let Some((open, _)) = delimiters {
                    out.push(open.into());
                }
                tokens(group.stream(), omitted, out);
                if let Some((_, close)) = delimiters {
                    out.push(close.into());
                }
            }
            other => out.push(other.to_string()),
        }
    }
}

fn unwraps(tokens: &[String]) -> usize {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, name)| {
            let name = name.strip_prefix("r#").unwrap_or(name);
            if !matches!(name, "unwrap" | "expect") || *index == 0 {
                return false;
            }
            let receiver = tokens[index - 1] == "."
                || (*index >= 2 && tokens[index - 2] == ":" && tokens[index - 1] == ":");
            // A method/associated call, including a turbofish; exclude fields and definitions.
            receiver
                && (tokens.get(index + 1).is_some_and(|s| s == "(")
                    || tokens
                        .get(index + 1..index + 4)
                        .is_some_and(|s| s == [":", ":", "<"]))
        })
        .count()
}

fn inspect(text: &str) -> Result<(Production, Vec<String>)> {
    let parsed = syn::parse_file(text)?;
    let mut production = Production::default();
    production.visit_file(&parsed);
    production.omitted.sort_unstable();
    let mut merged: Vec<Range> = Vec::new();
    for range in &production.omitted {
        if let Some(previous) = merged.last_mut().filter(|previous| previous.1 >= range.0) {
            previous.1 = previous.1.max(range.1);
        } else {
            merged.push(*range);
        }
    }
    production.omitted = merged;
    let mut out = Vec::new();
    tokens(text.parse()?, &production.omitted, &mut out);
    Ok((production, out))
}

// Stable FNV-1a over length-delimited UTF-8 tokens. Full tokens settle collisions.
fn window_hash(window: &[String]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for token in window {
        for byte in (token.len() as u64)
            .to_le_bytes()
            .iter()
            .chain(token.as_bytes())
        {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
    hash
}

#[derive(Default)]
struct Duplicates {
    seen: BTreeMap<u64, Vec<[u32; 40]>>,
    interned: BTreeMap<String, u32>,
    excess: usize,
}

impl Duplicates {
    fn add(&mut self, tokens: &[String]) {
        let ids: Vec<_> = tokens
            .iter()
            .map(|token| {
                let next = self.interned.len() as u32;
                *self.interned.entry(token.clone()).or_insert(next)
            })
            .collect();
        for (window, ids) in tokens.windows(40).zip(ids.windows(40)) {
            let bucket = self.seen.entry(window_hash(window)).or_default();
            if bucket.iter().any(|prior| prior == ids) {
                self.excess += 1;
            } else {
                let mut exact = [0; 40];
                exact.copy_from_slice(ids);
                bucket.push(exact);
            }
        }
    }
}

pub fn measure(root: &Path, commit: &str) -> Result<Snapshot> {
    let mut snapshot = Snapshot::new(commit);
    let mut duplicates = Duplicates::default();
    let mut modules = Modules::default();
    modules.file(&root.join("src/lib.rs"), false)?;
    for file in rust_files(root)? {
        let relative = file.strip_prefix(root)?;
        let path = relative.to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&file)?;
        let lines = text.lines().count();
        if lines > 800 {
            snapshot.files_over_800.push(LargeFile {
                path: path.clone(),
                lines,
            });
        }
        if test_path(relative)
            || (modules.tests.contains(&file) && !modules.production.contains(&file))
        {
            continue;
        }
        let (production, tokens) = inspect(&text).map_err(|error| format!("{path}: {error}"))?;
        snapshot.metrics.functions_over_60 += production.long_functions;
        snapshot.metrics.unwrap_expect += unwraps(&tokens);
        duplicates.add(&tokens);
    }
    snapshot.metrics.files_over_800 = snapshot.files_over_800.len();
    snapshot.metrics.duplicate_windows_40 = duplicates.excess;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_external_modules_are_excluded_but_shared_and_orphan_code_counts() -> Result<()> {
        let fixture = crate::test_support::fixture()?;
        let src = fixture.path.join("src");
        std::fs::write(
            src.join("lib.rs"),
            r#"
            #[cfg(test)] mod checks;
            #[path = "shared.rs"] mod live;
            #[cfg(test)] #[path = "shared.rs"] mod checking;
        "#,
        )?;
        std::fs::write(
            src.join("checks.rs"),
            "fn check() { x.unwrap(); } mod nested;",
        )?;
        std::fs::create_dir(src.join("checks"))?;
        std::fs::write(src.join("checks/nested.rs"), "fn check() { x.unwrap(); }")?;
        std::fs::write(src.join("shared.rs"), "fn shared() { x.unwrap(); }")?;
        std::fs::write(
            src.join("orphan.rs"),
            "fn unlinked() { x.expect(\"message\"); }",
        )?;
        assert_eq!(
            measure(&fixture.path, &fixture.commit)?
                .metrics
                .unwrap_expect,
            2
        );
        Ok(())
    }

    #[test]
    fn physical_file_threshold_includes_tests_and_exempts_no_path() -> Result<()> {
        let fixture = crate::test_support::fixture()?;
        let src = fixture.path.join("src");
        std::fs::write(src.join("lib.rs"), "#[cfg(test)] mod checks;\n")?;
        std::fs::write(src.join("checks.rs"), "// test code\n".repeat(801))?;
        std::fs::write(src.join("small.rs"), "// line\n".repeat(800))?;
        let wordlists = src.join("compat/bip39/wordlists");
        std::fs::create_dir_all(&wordlists)?;
        std::fs::write(wordlists.join("english.rs"), "// data\n".repeat(801))?;
        std::fs::write(wordlists.join("new_code.rs"), "// code\n".repeat(801))?;
        let snapshot = measure(&fixture.path, &fixture.commit)?;
        assert_eq!(snapshot.metrics.files_over_800, 3);
        assert_eq!(snapshot.files_over_800[0].path, "src/checks.rs");
        assert_eq!(
            snapshot.files_over_800[1].path,
            "src/compat/bip39/wordlists/english.rs"
        );
        assert_eq!(
            snapshot.files_over_800[2].path,
            "src/compat/bip39/wordlists/new_code.rs"
        );
        Ok(())
    }

    #[test]
    fn calls_in_macros_count_but_comments_strings_fields_and_test_code_do_not() -> Result<()> {
        let (_, tokens) = inspect(
            r###"
            /// .unwrap() must not count
            fn live() {
                // value.expect("comment")
                let _ = r#"value.unwrap()"#;
                let _ = value.unwrap;
                let _ = value.unwrap_or(0);
                value.unwrap();
                wrap!(value.expect("message"));
                Option::unwrap(value);
                value.expect::<u8>("message");
                value.r#unwrap();
                #[cfg(test)] value.unwrap();
            }
            #[cfg(test)] mod checks { fn check() { value.unwrap(); } }
            #[test] fn check() { value.unwrap(); }
            #[cfg(all(test, feature = "a"))] fn hidden() { value.unwrap(); }
            #[cfg(any(test, feature = "a"))] fn maybe_live() { value.unwrap(); }
            #[cfg(not(test))] fn live_without_tests() { value.unwrap(); }
        "###,
        )?;
        assert_eq!(unwraps(&tokens), 7);
        Ok(())
    }

    #[test]
    fn function_body_threshold_includes_braces_but_excludes_test_methods() -> Result<()> {
        let small = format!("fn small() {{\n{}}}", "\n".repeat(58));
        let large = format!("fn large() {{\n{}}}", "\n".repeat(59));
        assert_eq!(inspect(&small)?.0.long_functions, 0);
        assert_eq!(inspect(&large)?.0.long_functions, 1);
        assert_eq!(
            inspect(&format!("#[cfg(test)] {large}"))?.0.long_functions,
            0
        );
        assert_eq!(
            inspect(&format!("impl X {{ #[cfg(test)] {large} }}"))?
                .0
                .long_functions,
            0
        );
        assert_eq!(
            inspect(&format!("trait X {{ {large} }}"))?.0.long_functions,
            1
        );
        Ok(())
    }

    #[test]
    fn duplicate_windows_count_repeated_occurrences_without_cross_file_windows() {
        let tokens: Vec<_> = (0..41).map(|index| format!("token{index}")).collect();
        let mut duplicates = Duplicates::default();
        duplicates.add(&tokens[..39]);
        duplicates.add(&tokens[39..]);
        assert_eq!(duplicates.excess, 0);
        duplicates.add(&tokens);
        assert_eq!(duplicates.excess, 0);
        duplicates.add(&tokens);
        assert_eq!(duplicates.excess, 2);
        assert_ne!(
            window_hash(&["ab".into(), "c".into()]),
            window_hash(&["a".into(), "bc".into()])
        );
    }

    #[test]
    fn only_paths_under_a_tests_component_are_test_paths() {
        assert!(test_path(Path::new("src/example/tests/check.rs")));
        assert!(!test_path(Path::new("src/contest.rs")));
    }
}

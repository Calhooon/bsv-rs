//! How the crate holds its own ECDH secrets (the bucket #912, lines 1 and 2),
//! lexically, over the non-test code of every file under `src/`:
//!
//! (1) no call of `mul_scalar` takes an argument that calls `to_bytes`: a
//! point is multiplied by a private key through `PublicKey::mul_secret`,
//! which reads the scalar from `PrivateKey::secret_scalar` and exports no
//! byte copy of it; (2) `secret_scalar`'s return type names `Zeroizing`, so
//! the scalar it lends is wiped when dropped; (3) the hand-written
//! `impl PartialEq for PublicKey` calls `ct_eq` and holds no `=` (so no
//! `==` over the bytes): a `PublicKey` can hold a secret point
//! (`SharedSecret::to_point`, `mul_scalar`).
//!
//! The scan's bound: tokens as written, so a scalar copied into a binding
//! on one line and passed on the next, a multiplication under another
//! name, or an alias of `Zeroizing` is not seen; what a wipe leaves in
//! memory (a moved value's old place, the arithmetic's own temporaries) is
//! no claim of this file.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::{group_end, is_call, Source, Token};

fn source(text: &str) -> Source {
    Source {
        path: String::new(),
        text: text.to_owned(),
    }
}

/// The lines of `mul_scalar` calls whose argument calls `to_bytes`.
fn scalar_copies(tokens: &[Token<'_>]) -> Vec<usize> {
    let mut found = Vec::new();
    for at in 0..tokens.len() {
        if !is_call(tokens, at, &["mul_scalar"]) || tokens[at + 1].text != "(" {
            continue;
        }
        let end = group_end(tokens, at + 1);
        if tokens[at + 1..end]
            .iter()
            .any(|t| !t.literal && t.text == "to_bytes")
        {
            found.push(tokens[at].line);
        }
    }
    found
}

/// The tokens from the `fn` named `name` to its body's opening brace.
fn signature<'a>(tokens: &'a [Token<'a>], name: &str) -> Option<&'a [Token<'a>]> {
    let at = tokens
        .windows(2)
        .position(|w| w[0].text == "fn" && w[1].text == name)?;
    let open = tokens[at..].iter().position(|t| t.text == "{")?;
    Some(&tokens[at..at + open])
}

/// The body of `impl PartialEq for PublicKey`, when the text holds one.
fn public_key_eq_body<'a>(tokens: &'a [Token<'a>]) -> Option<&'a [Token<'a>]> {
    let header = ["impl", "PartialEq", "for", "PublicKey", "{"];
    let at = tokens
        .windows(header.len())
        .position(|w| w.iter().map(|t| t.text).eq(header))?;
    let open = at + header.len() - 1;
    Some(&tokens[open..group_end(tokens, open)])
}

fn eq_refusal(tokens: &[Token<'_>]) -> Option<&'static str> {
    let Some(body) = public_key_eq_body(tokens) else {
        return Some("no hand-written `impl PartialEq for PublicKey`");
    };
    if !body.iter().any(|t| !t.literal && t.text == "ct_eq") {
        return Some("`PublicKey`'s `eq` does not call `ct_eq`");
    }
    if body.iter().any(|t| !t.literal && t.text.contains('=')) {
        return Some("`PublicKey`'s `eq` holds an `=`");
    }
    None
}

#[test]
fn no_private_scalar_is_copied_out_for_a_point_multiplication_912() {
    let mut sites = Vec::new();
    for file in arch_support::sources() {
        for line in scalar_copies(&file.tokens()) {
            sites.push(format!("{}:{line}: {}", file.path, file.line(line)));
        }
    }
    assert!(
        sites.is_empty(),
        "a private scalar is copied out through `to_bytes` for `mul_scalar`; \
         multiply through `mul_secret`:\n{}",
        sites.join("\n")
    );

    // The rule refuses each spelling it names and passes the door.
    for planted in [
        "fn f() { b.mul_scalar(&self.to_bytes()) }",
        "fn f() { PublicKey::mul_scalar(&b, &key.to_bytes())?; }",
        "fn f() { b.mul_scalar(&Zeroizing::new(k.to_bytes())) }",
    ] {
        assert_eq!(
            scalar_copies(&source(planted).tokens()).len(),
            1,
            "{planted}"
        );
    }
    for passing in [
        "fn f() { b.mul_secret(self) }",
        "fn f() { b.mul_scalar(&e_bytes) }",
        "fn f() { let s = \"mul_scalar(&k.to_bytes())\"; }",
    ] {
        assert!(
            scalar_copies(&source(passing).tokens()).is_empty(),
            "{passing}"
        );
    }
}

#[test]
fn the_scalar_the_private_key_lends_is_wiped_when_dropped_912() {
    let file = source(&arch_support::read("src/primitives/ec/private_key.rs"));
    let tokens = file.tokens();
    let signature = signature(&tokens, "secret_scalar")
        .expect("`PrivateKey::secret_scalar` is in src/primitives/ec/private_key.rs");
    let arrow = signature
        .iter()
        .position(|t| t.text == ">" || t.text == "->")
        .expect("`secret_scalar` returns a value");
    assert!(
        signature[arrow..].iter().any(|t| t.text == "Zeroizing"),
        "`secret_scalar` returns its scalar outside `Zeroizing`"
    );

    let key = source(&arch_support::read("src/primitives/ec/public_key.rs"));
    let key_tokens = key.tokens();
    let door = signature_and_body(&key_tokens, "mul_secret");
    assert!(
        door.iter().any(|t| t.text == "secret_scalar"),
        "`mul_secret` does not read the scalar through `secret_scalar`"
    );
    assert!(
        !door.iter().any(|t| t.text == "to_bytes"),
        "`mul_secret` copies the scalar out through `to_bytes`"
    );
}

/// The tokens of the `fn` named `name`, its body included.
fn signature_and_body<'a>(tokens: &'a [Token<'a>], name: &str) -> &'a [Token<'a>] {
    let at = tokens
        .windows(2)
        .position(|w| w[0].text == "fn" && w[1].text == name)
        .unwrap_or_else(|| panic!("no `fn {name}`"));
    let open = at
        + tokens[at..]
            .iter()
            .position(|t| t.text == "{")
            .unwrap_or_else(|| panic!("`fn {name}` has no body"));
    &tokens[at..group_end(tokens, open)]
}

#[test]
fn public_key_equality_reads_its_bytes_without_an_early_exit_912() {
    let file = source(&arch_support::read("src/primitives/ec/public_key.rs"));
    assert_eq!(eq_refusal(&file.tokens()), None);

    // The rule refuses the comparison it replaced, a derive and a body that
    // keeps both.
    for planted in [
        "impl PartialEq for PublicKey { fn eq(&self, o: &Self) -> bool { self.to_compressed() == o.to_compressed() } }",
        "#[derive(Clone, PartialEq)] pub struct PublicKey { inner: K }",
        "impl PartialEq for PublicKey { fn eq(&self, o: &Self) -> bool { self.a == o.a && bool::from(self.b().ct_eq(&o.b())) } }",
    ] {
        assert!(eq_refusal(&source(planted).tokens()).is_some(), "{planted}");
    }
    let passing = "impl PartialEq for PublicKey { fn eq(&self, o: &Self) -> bool { self.to_compressed().ct_eq(&o.to_compressed()).into() } }";
    assert_eq!(eq_refusal(&source(passing).tokens()), None);
}

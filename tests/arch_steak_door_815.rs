//! A host's STEAK is judged at every door it comes through (#815's fold).
//!
//! The finding: the broadcaster's validator (`topic_broadcaster/steak.rs`)
//! judged a typed `Steak`, and the shipped HTTPS facilitator built that
//! type with `response.json::<Steak>()`, which drops what the type cannot
//! hold: an instruction with a fourth field, a `coinsRemoved` of `null`, a
//! body of any size were taken, where the reference refuses each
//! (`ts-stack@edf6e03` `SHIPBroadcaster.ts:251-256`, `:261-265`,
//! `:272-297`). The class: a door that turns a host's bytes into a `Steak`
//! without the reference's reading, or a broadcaster path that counts a
//! `Steak` it did not judge.
//!
//! The doors, by signature, over every `.rs` file under `src/` (lexical:
//! comments and literals opaque, `#[cfg(test)]` items skipped):
//!
//! 1. Every `impl OverlayBroadcastFacilitator for X` is listed in `DOORS`
//!    (one: the HTTPS facilitator). A new implementor inside this crate is
//!    refused until it is listed, which is the moment its read is reviewed.
//! 2. The HTTPS facilitator's file reads a `/submit` answer through
//!    `steak_body::Answer` alone (built once from the declared length,
//!    ended in `answer.steak(&tagged_beef.topics)`), and no `.json()`,
//!    `.bytes().await` or `.text().await` anywhere in that file or the
//!    reader's (a response's whole-body readers: each buffers a body of any
//!    size, and `.json()` builds the type unjudged); `Answer::steak` is
//!    `read_steak(&self.0, sent)`, the judge of the JSON.
//! 3. No file under `src/` reads a `Steak` from text by serde: no
//!    `from_slice`, `from_str`, `from_value`, `from_reader` or `json`
//!    turbofished or annotated to `Steak`.
//! 4. The one call of a broadcast facilitator's `send` is the
//!    broadcaster's, and what it returns reaches `host_acks` and
//!    `HostResponse::success` only through `steak::judge`'s `TakenSteak`,
//!    whose one constructor is in `judge` (the compiler holds the rest:
//!    the tuple field is private to `steak.rs`, the type derives nothing).
//!
//! What the scan cannot see: a `Steak` built field by field from a parsed
//! `Value` in another file, a type alias of `Steak`, a facilitator
//! implemented by a dependent (its typed `Steak` is judged by the
//! broadcaster, rule 4, which is every state that type can hold).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

/// Every implementor of the broadcast facilitator under `src/`.
const DOORS: [(&str, &str); 1] = [(
    "src/overlay/facilitators.rs",
    "HttpsOverlayBroadcastFacilitator",
)];

const FACILITATORS: &str = "src/overlay/facilitators.rs";
const READER: &str = "src/overlay/facilitators/steak_body.rs";
const BROADCASTER: &str = "src/overlay/topic_broadcaster.rs";
const JUDGE: &str = "src/overlay/topic_broadcaster/steak.rs";
const TYPES: &str = "src/overlay/types.rs";

/// A file's code tokens joined by one space, a space at each end.
fn joined(text: &str) -> String {
    let tokens = arch_support::code_tokens(text, false);
    let mut out = String::from(" ");
    for token in tokens {
        out.push_str(token.text);
        out.push(' ');
    }
    out
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Every refusal of the tree `files` (`(path, text)`).
fn refusals(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let get = |path: &str| {
        files
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, text)| joined(text))
            .unwrap_or_default()
    };

    // 1. The implementors are the listed doors
    for (path, text) in files {
        let code = joined(text);
        for (at, _) in code.match_indices(" impl OverlayBroadcastFacilitator for ") {
            let name = code[at..].split(' ').nth(4).unwrap_or_default();
            if !DOORS.contains(&(path.as_str(), name)) {
                out.push(format!(
                    "{path}: `{name}` implements OverlayBroadcastFacilitator and is not in DOORS"
                ));
            }
        }
    }
    for (path, name) in DOORS {
        let needle = format!(" impl OverlayBroadcastFacilitator for {name} ");
        if count(&get(path), &needle) != 1 {
            out.push(format!("{path}: DOORS names `{name}`, which is not there"));
        }
    }

    // 2. The HTTPS door reads through the reader alone
    let door = get(FACILITATORS);
    if count(&door, " steak_body :: Answer :: declared ( ") != 1
        || count(&door, " answer . steak ( & tagged_beef . topics ) } ") != 1
    {
        out.push(format!(
            "{FACILITATORS}: `send` must read through one `steak_body::Answer` and end in `answer.steak(&tagged_beef.topics)`"
        ));
    }
    for path in [FACILITATORS, READER] {
        let code = get(path);
        for buffered in [
            " . json ( ) ",
            " . bytes ( ) . await ",
            " . text ( ) . await ",
        ] {
            if code.contains(buffered) {
                out.push(format!(
                    "{path}: `{}` buffers a body of any size",
                    buffered.replace(' ', "").replace(".await", "")
                ));
            }
        }
    }
    if count(
        &get(READER),
        " Result < Steak > { read_steak ( & self . 0 , sent ) } ",
    ) != 1
    {
        out.push(format!(
            "{READER}: `Answer::steak` must be `read_steak(&self.0, sent)`"
        ));
    }

    // 3. No serde read of a `Steak` from text
    for (path, text) in files {
        let code = joined(text);
        for reader in [
            "from_slice",
            "from_str",
            "from_value",
            "from_reader",
            "json",
        ] {
            if code.contains(&format!(" {reader} :: < Steak > "))
                || code.contains(&format!(
                    " {reader} :: < crate :: overlay :: types :: Steak > "
                ))
            {
                out.push(format!(
                    "{path}: `{reader}::<Steak>` reads a STEAK unjudged"
                ));
            }
        }
        for (at, _) in code.match_indices(" : Steak = ") {
            let statement = code[at..].split(" ; ").next().unwrap_or_default();
            if [
                "serde_json",
                " json ",
                "from_slice",
                "from_str",
                "from_value",
            ]
            .iter()
            .any(|reader| statement.contains(reader))
            {
                out.push(format!("{path}: a `Steak` binding read by serde, unjudged"));
            }
        }
    }

    // 4. The broadcaster counts a judged STEAK alone
    for (path, text) in files {
        let code = joined(text);
        let sends = count(&code, " facilitator . send ( ");
        if sends != usize::from(path == BROADCASTER) {
            out.push(format!(
                "{path}: {sends} calls of `facilitator.send(`; the broadcaster's one call is the door"
            ));
        }
        let successes = count(&code, " HostResponse :: success ( ");
        let judged = count(
            &code,
            " HostResponse :: success ( host , taken . into_steak ( ) ) ",
        );
        if path != TYPES && (successes != judged || (path != BROADCASTER && successes != 0)) {
            out.push(format!(
                "{path}: `HostResponse::success(` takes `taken.into_steak()` in the broadcaster alone"
            ));
        }
        let acks = count(&code, " host_acks . insert ( ");
        if acks
            != count(
                &code,
                " host_acks . insert ( host . clone ( ) , taken . acknowledged ( ) ) ",
            )
        {
            out.push(format!(
                "{path}: `host_acks.insert(` takes `taken.acknowledged()` alone"
            ));
        }
        let built = count(&code, " TakenSteak ( ");
        let allowed = if path == JUDGE { 2 } else { 0 };
        if built != allowed {
            out.push(format!(
                "{path}: {built} `TakenSteak(`; the declaration and `judge`'s `Ok(TakenSteak(steak))` alone"
            ));
        }
    }
    let broadcaster = get(BROADCASTER);
    if count(
        &broadcaster,
        " match steak :: judge ( steak , & sent ) { Ok ( taken ) = > ",
    ) != 1
    {
        out.push(format!(
            "{BROADCASTER}: the sent STEAK must be matched through `steak::judge(steak, &sent)`"
        ));
    }
    let judge = get(JUDGE);
    for needle in [
        " pub ( super ) struct TakenSteak ( Steak ) ; ",
        " validate_steak ( & steak , sent ) ? ; Ok ( TakenSteak ( steak ) ) } ",
    ] {
        if count(&judge, needle) != 1 {
            out.push(format!("{JUDGE}: expected once: `{}`", needle.trim()));
        }
    }
    if files
        .iter()
        .find(|(p, _)| p == JUDGE)
        .is_some_and(|(_, text)| text.contains("]\npub(super) struct TakenSteak"))
    {
        out.push(format!(
            "{JUDGE}: `TakenSteak` carries an attribute (a derive builds one)"
        ));
    }
    out
}

fn tree() -> Vec<(String, String)> {
    arch_support::sources()
        .into_iter()
        .map(|s| (s.path, s.text))
        .collect()
}

/// The tree with `from` replaced by `to` in `path` (once, and present).
fn planted(path: &str, from: &str, to: &str) -> Vec<(String, String)> {
    let mut files = tree();
    let file = files
        .iter_mut()
        .find(|(p, _)| p == path)
        .unwrap_or_else(|| panic!("{path} is not under src/"));
    assert!(file.1.contains(from), "{path} no longer holds `{from}`");
    file.1 = file.1.replacen(from, to, 1);
    files
}

#[test]
fn a_hosts_steak_is_judged_at_every_door_it_comes_through_815() {
    let refused = refusals(&tree());
    assert!(refused.is_empty(), "{}", refused.join("\n"));
}

/// Each rule refuses its planted fault, by name.
#[test]
fn a_door_without_the_judge_is_refused_815() {
    let cases: [(&str, &str, &str, &str); 9] = [
        // The finding as it stood: a typed read at the HTTPS door
        (
            FACILITATORS,
            "answer.steak(&tagged_beef.topics)",
            "response.json().await.map_err(|e| Error::OverlayError(e.to_string()))",
            "`send` must read through one `steak_body::Answer`",
        ),
        (
            FACILITATORS,
            "answer.steak(&tagged_beef.topics)",
            "{ let _ = response.bytes().await; answer.steak(&tagged_beef.topics) }",
            "`.bytes()` buffers a body of any size",
        ),
        (
            FACILITATORS,
            "answer.steak(&tagged_beef.topics)",
            "{ let steak: Steak = serde_json::from_slice(&[]).unwrap_or_default(); let _ = steak; answer.steak(&tagged_beef.topics) }",
            "a `Steak` binding read by serde, unjudged",
        ),
        (
            TYPES,
            "pub type Steak = HashMap<String, AdmittanceInstructions>;",
            "pub type Steak = HashMap<String, AdmittanceInstructions>;\npub fn read(b: &[u8]) -> Option<Steak> { serde_json::from_slice::<Steak>(b).ok() }",
            "`from_slice::<Steak>` reads a STEAK unjudged",
        ),
        (
            READER,
            "        read_steak(&self.0, sent)",
            "        serde_json::from_slice(&self.0).map_err(|_| too_large())",
            "`Answer::steak` must be `read_steak(&self.0, sent)`",
        ),
        // A second implementor inside the crate
        (
            TYPES,
            "pub type Steak = HashMap<String, AdmittanceInstructions>;",
            "pub type Steak = HashMap<String, AdmittanceInstructions>;\nimpl OverlayBroadcastFacilitator for Other {}",
            "`Other` implements OverlayBroadcastFacilitator and is not in DOORS",
        ),
        // The broadcaster counting a STEAK it did not judge
        (
            BROADCASTER,
            "host_responses.push(HostResponse::success(host, taken.into_steak()));",
            "host_responses.push(HostResponse::success(host, Steak::new()));",
            "`HostResponse::success(` takes `taken.into_steak()` in the broadcaster alone",
        ),
        (
            BROADCASTER,
            "match steak::judge(steak, &sent) {",
            "match Ok::<_, String>(steak::TakenSteak(steak)) {",
            "1 `TakenSteak(`",
        ),
        (
            JUDGE,
            "    validate_steak(&steak, sent)?;\n    Ok(TakenSteak(steak))",
            "    Ok(TakenSteak(steak))",
            "expected once: `validate_steak ( & steak , sent ) ? ; Ok ( TakenSteak ( steak ) ) }`",
        ),
    ];
    for (path, from, to, message) in cases {
        let refused = refusals(&planted(path, from, to));
        assert!(
            refused.iter().any(|r| r.contains(message)),
            "planting `{to}` in {path}: no refusal holds `{message}`:\n{}",
            refused.join("\n")
        );
    }
}

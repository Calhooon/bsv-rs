//! A host's STEAK judged as the reference judges it (#815;
//! `ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
//! `validateSTEAK(steak, [...topics])` (`:240-269`) over the topics sent to
//! that host (`:492`), each index list by `validateInstructionIndexes`
//! (`:222-238`). A refusal fails the host (`:494-496`).
//!
//! The typed [`Steak`] cannot hold three of the states the reference
//! checks: a value that is no plain record, an instruction with a field
//! other than the three, and an index that is no integer from 0 to
//! `0xffffffff`. A custom facilitator cannot build them; the HTTPS
//! facilitator, which reads them from a host's bytes, judges the JSON
//! itself before it builds the type, in the reference's words
//! (`facilitators/steak_body.rs`, #815's fold; until the fold a typed read
//! took an instruction with a fourth field and a `coinsRemoved` of `null`).
//! `Steak` is a `HashMap`, so where two entries break a rule the one named
//! is unspecified (the reference names the earlier in the body's order);
//! the words are one of the reference's either way.

use super::requirements::MAX_SHIP_TOPICS;
use crate::overlay::types::Steak;
use std::collections::HashSet;

/// `MAX_SHIP_INSTRUCTION_INDEXES` (`:96`): the indexes one list may carry.
const MAX_SHIP_INSTRUCTION_INDEXES: usize = 4096;

/// `validateInstructionIndexes(value, label)` (`:222-238`): at most 4096
/// indexes, none repeated, else `SHIP <label> is invalid.`.
fn instruction_indexes(indexes: &[u32], label: &str) -> Result<(), String> {
    if indexes.len() > MAX_SHIP_INSTRUCTION_INDEXES {
        return Err(format!("SHIP {label} is invalid."));
    }
    let mut seen = HashSet::with_capacity(indexes.len());
    if indexes.iter().all(|index| seen.insert(*index)) {
        Ok(())
    } else {
        Err(format!("SHIP {label} is invalid."))
    }
}

/// A STEAK the judge took (#815's fold). [`judge`] is its one constructor,
/// so the broadcaster cannot count a host's acknowledgment or report a
/// host's success from a STEAK that was not judged: both read through this
/// type (`tests/arch_steak_door_815.rs` pins the constructor and the two
/// uses).
pub(super) struct TakenSteak(Steak);

impl TakenSteak {
    /// The topics the host acknowledged: those whose instructions record
    /// activity (`:519-531`).
    pub(super) fn acknowledged(&self) -> HashSet<String> {
        self.0
            .iter()
            .filter(|(_, instructions)| instructions.has_activity())
            .map(|(topic, _)| topic.clone())
            .collect()
    }

    /// The STEAK itself, for the host's success.
    pub(super) fn into_steak(self) -> Steak {
        self.0
    }
}

/// A host's STEAK as the reference's broadcaster judges it (`:486-496`):
/// the empty one `Steak has no topics.`, then `validateSTEAK` over the
/// topics `sent` to that host. An `Err` is a failed host, in its words.
pub(super) fn judge(steak: Steak, sent: &HashSet<String>) -> Result<TakenSteak, String> {
    if steak.is_empty() {
        return Err("Steak has no topics.".into());
    }
    validate_steak(&steak, sent)?;
    Ok(TakenSteak(steak))
}

/// `validateSTEAK(value, topics)` (`:240-269`): at most 64 topics, else
/// `SHIP response contains too many topics.`; each a topic sent to the
/// host, else `SHIP response acknowledged an unexpected topic.`; then its
/// `outputsToAdmit`, `coinsToRetain` and, when present, `coinsRemoved`.
/// [`judge`] has refused the empty STEAK (`Steak has no topics.`,
/// `:486-488`).
fn validate_steak(steak: &Steak, sent: &HashSet<String>) -> Result<(), String> {
    if steak.len() > MAX_SHIP_TOPICS {
        return Err("SHIP response contains too many topics.".into());
    }
    for (topic, instructions) in steak {
        if !sent.contains(topic) {
            return Err("SHIP response acknowledged an unexpected topic.".into());
        }
        instruction_indexes(&instructions.outputs_to_admit, "outputsToAdmit")?;
        instruction_indexes(&instructions.coins_to_retain, "coinsToRetain")?;
        if let Some(removed) = &instructions.coins_removed {
            instruction_indexes(removed, "coinsRemoved")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::types::AdmittanceInstructions;

    fn sent(topics: &[&str]) -> HashSet<String> {
        topics.iter().map(|t| t.to_string()).collect()
    }

    fn steak(entries: &[(&str, AdmittanceInstructions)]) -> Steak {
        entries
            .iter()
            .map(|(t, i)| (t.to_string(), i.clone()))
            .collect()
    }

    fn admit(indexes: Vec<u32>) -> AdmittanceInstructions {
        AdmittanceInstructions {
            outputs_to_admit: indexes,
            ..Default::default()
        }
    }

    #[test]
    fn a_steak_of_the_sent_topics_with_distinct_indexes_passes_815() {
        let s = steak(&[("tm_a", admit(vec![0, 1])), ("tm_b", admit(vec![]))]);
        assert_eq!(validate_steak(&s, &sent(&["tm_a", "tm_b"])), Ok(()));
        let full = admit((0..4096).collect());
        assert_eq!(
            validate_steak(&steak(&[("tm_a", full)]), &sent(&["tm_a"])),
            Ok(())
        );
    }

    #[test]
    fn each_refusal_is_in_the_references_words_815() {
        let topics: Vec<String> = (0..65).map(|i| format!("tm_{i}")).collect();
        let many: Steak = topics
            .iter()
            .map(|t| (t.clone(), AdmittanceInstructions::default()))
            .collect();
        let all: HashSet<String> = topics.iter().cloned().collect();
        assert_eq!(
            validate_steak(&many, &all),
            Err("SHIP response contains too many topics.".into())
        );
        let sixty_four: Steak = many.into_iter().take(64).collect();
        assert_eq!(validate_steak(&sixty_four, &all), Ok(()));
        assert_eq!(
            validate_steak(&steak(&[("tm_b", admit(vec![]))]), &sent(&["tm_a"])),
            Err("SHIP response acknowledged an unexpected topic.".into())
        );
        assert_eq!(
            validate_steak(&steak(&[("tm_a", admit(vec![3, 3]))]), &sent(&["tm_a"])),
            Err("SHIP outputsToAdmit is invalid.".into())
        );
        let retain = AdmittanceInstructions {
            coins_to_retain: (0..4097).collect(),
            ..Default::default()
        };
        assert_eq!(
            validate_steak(&steak(&[("tm_a", retain)]), &sent(&["tm_a"])),
            Err("SHIP coinsToRetain is invalid.".into())
        );
        let removed = AdmittanceInstructions {
            coins_removed: Some(vec![1, 2, 1]),
            ..Default::default()
        };
        assert_eq!(
            validate_steak(&steak(&[("tm_a", removed)]), &sent(&["tm_a"])),
            Err("SHIP coinsRemoved is invalid.".into())
        );
        // The three lists in the reference's order (`:258-266`)
        let both = AdmittanceInstructions {
            outputs_to_admit: vec![0, 0],
            coins_to_retain: vec![1, 1],
            coins_removed: Some(vec![2, 2]),
        };
        assert_eq!(
            validate_steak(&steak(&[("tm_a", both)]), &sent(&["tm_a"])),
            Err("SHIP outputsToAdmit is invalid.".into())
        );
    }
}

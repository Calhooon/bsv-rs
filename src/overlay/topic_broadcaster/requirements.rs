//! The acknowledgment requirements as the reference has them
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
//! a requirement's topic list checked at construction
//! (`snapshotAcknowledgmentRequirement`, `:182-193`, called at `:430-444`
//! and per specific host at `:212-216`), the three checks over a map seeded
//! with every interested host (`:511-512`) in the reference's order and
//! with its three failure codes (`:538-546`, `:555-622`).

use super::{RequireAck, TopicBroadcaster};
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};

/// `MAX_SHIP_TOPICS` (`:95`): the topics a broadcast, a requirement or a
/// STEAK may name.
pub(super) const MAX_SHIP_TOPICS: usize = 64;

/// The reference's `/^(?=.{1,50}$)tm_[a-z]+(?:_[a-z]+)*$/` (`:171`).
fn canonical_topic(topic: &str) -> bool {
    let Some(rest) = topic.strip_prefix("tm_") else {
        return false;
    };
    topic.len() <= 50
        && rest
            .split('_')
            .all(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase()))
}

/// `canonicalTopics(value, label, allowEmpty)` (`:156-180`): at most 64
/// names (and at least one unless `allow_empty`), else
/// `<label> must be a bounded array of canonical topic names.`; each a
/// canonical `tm_` name seen once, else
/// `<label> must contain unique canonical tm_ topic names.`. Read for the
/// broadcast topics (`:420`, label `Broadcast topics`, #815) and for each
/// requirement's list (`allow_empty`, `:186`).
pub(super) fn canonical_topics(topics: &[String], label: &str, allow_empty: bool) -> Result<()> {
    if (!allow_empty && topics.is_empty()) || topics.len() > MAX_SHIP_TOPICS {
        return Err(Error::OverlayError(format!(
            "{label} must be a bounded array of canonical topic names."
        )));
    }
    let mut seen = HashSet::new();
    for topic in topics {
        if !canonical_topic(topic) || !seen.insert(topic.as_str()) {
            return Err(Error::OverlayError(format!(
                "{label} must contain unique canonical tm_ topic names."
            )));
        }
    }
    Ok(())
}

/// `snapshotAcknowledgmentRequirement(value, topics, label)` (`:182-193`):
/// `All` and `Any` (`'all'`, `'any'`) taken as given; a list read by
/// `canonicalTopics(value, label, true)` and refused when it names a
/// topic outside the broadcast's; `None` has no reference form (the
/// reference's empty list, which this check passes) and is taken as given.
pub(super) fn snapshot(requirement: &RequireAck, topics: &[String], label: &str) -> Result<()> {
    let RequireAck::Some(required) = requirement else {
        return Ok(());
    };
    canonical_topics(required, label, true)?;
    if required.iter().any(|topic| !topics.contains(topic)) {
        return Err(Error::OverlayError(format!(
            "{label} may only reference topics included in this broadcast."
        )));
    }
    Ok(())
}

/// The failed requirement, by the check that failed (`:568-574`,
/// `:592-598`, `:611-617`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AckFailure {
    AllHosts,
    AnyHost,
    SpecificHosts,
}

impl AckFailure {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::AllHosts => "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED",
            Self::AnyHost => "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED",
            Self::SpecificHosts => "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED",
        }
    }

    pub(super) fn description(self) -> &'static str {
        match self {
            Self::AllHosts => "Not all hosts acknowledged the required topics.",
            Self::AnyHost => "No host acknowledged the required topics.",
            Self::SpecificHosts => "Specific hosts did not acknowledge the required topics.",
        }
    }
}

/// `#topicsMatchRequirement` (`:624-634`).
fn matches(acknowledged: &HashSet<String>, required: &[String], require_all: bool) -> bool {
    if require_all {
        required.iter().all(|t| acknowledged.contains(t))
    } else {
        required.iter().any(|t| acknowledged.contains(t))
    }
}

/// The acknowledgment map the checks read: every interested host seeded
/// with an empty set (`:511-512`), then each successful host's
/// acknowledged topics (`:514-534`). A host that failed, or answered
/// nothing, stays an acknowledgment of nothing.
pub(super) fn seeded<'a>(
    interested: impl IntoIterator<Item = &'a String>,
    successful: HashMap<String, HashSet<String>>,
) -> HashMap<String, HashSet<String>> {
    let mut acks: HashMap<String, HashSet<String>> = interested
        .into_iter()
        .map(|host| (host.clone(), HashSet::new()))
        .collect();
    acks.extend(successful);
    acks
}

impl TopicBroadcaster {
    /// The three checks in the reference's order (`:538-546`): all hosts,
    /// any host, specific hosts; the earliest failing one's.
    pub(super) fn check_acknowledgments(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> std::result::Result<(), AckFailure> {
        self.check_all_hosts_requirement(host_acks)?;
        self.check_any_host_requirement(host_acks)?;
        self.check_specific_hosts_requirement(host_acks)
    }

    /// `checkAllHostsRequirement` through `#resolveAllHostsRequirement`
    /// (`:555-576`): `Any` every topic, one each; `All` every topic, all
    /// each; a list its topics, all each; an empty list (or `None`) no
    /// check; every host of the map judged (`:636-644`).
    pub(super) fn check_all_hosts_requirement(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> std::result::Result<(), AckFailure> {
        let (required, require_all): (&[String], bool) = match &self.require_ack_from_all_hosts {
            RequireAck::None => return Ok(()),
            RequireAck::Any => (&self.topics, false),
            RequireAck::All => (&self.topics, true),
            RequireAck::Some(topics) => (topics, true),
        };
        if required.is_empty() {
            return Ok(());
        }
        if host_acks
            .values()
            .all(|acked| matches(acked, required, require_all))
        {
            Ok(())
        } else {
            Err(AckFailure::AllHosts)
        }
    }

    /// `#checkAnyHostRequirement` through `#resolveAnyHostRequirement`
    /// (`:578-600`): `All` every topic, all at one host; `Any` every topic,
    /// one at one host; a list its topics, all at one host (`require:
    /// 'all'`, `:584`); an empty list (or `None`) no check (`:646-654`).
    pub(super) fn check_any_host_requirement(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> std::result::Result<(), AckFailure> {
        let (required, require_all): (&[String], bool) = match &self.require_ack_from_any_host {
            RequireAck::None => return Ok(()),
            RequireAck::Any => (&self.topics, false),
            RequireAck::All => (&self.topics, true),
            RequireAck::Some(topics) => (topics, true),
        };
        if required.is_empty() {
            return Ok(());
        }
        if host_acks
            .values()
            .any(|acked| matches(acked, required, require_all))
        {
            Ok(())
        } else {
            Err(AckFailure::AnyHost)
        }
    }

    /// `checkSpecificHostsRequirement` and
    /// `checkAcknowledgmentFromSpecificHosts` (`:602-622`, `:656-684`): a
    /// required host absent from the map (not interested) fails; `All` and
    /// `Any` the broadcast's topics; a list its topics, all; `None` (no
    /// reference form, as its `continue` for an invalid configuration)
    /// asks only that the host be in the map.
    pub(super) fn check_specific_hosts_requirement(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> std::result::Result<(), AckFailure> {
        for (host, requirement) in &self.require_ack_from_specific_hosts {
            let Some(acked) = host_acks.get(host) else {
                return Err(AckFailure::SpecificHosts);
            };
            let (required, require_all): (&[String], bool) = match requirement {
                RequireAck::None => continue,
                RequireAck::All => (&self.topics, true),
                RequireAck::Any => (&self.topics, false),
                RequireAck::Some(topics) => (topics, true),
            };
            if !matches(acked, required, require_all) {
                return Err(AckFailure::SpecificHosts);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_topic_is_the_references_pattern_tb_acks() {
        for t in [
            "tm_a",
            "tm_ship_discovery",
            &format!("tm_{}", "a".repeat(47)),
        ] {
            assert!(canonical_topic(t), "{t}");
        }
        for t in [
            "tm_",
            "tm_A",
            "tm__a",
            "tm_a_",
            "tm_a1",
            "ls_a",
            &format!("tm_{}", "a".repeat(48)),
        ] {
            assert!(!canonical_topic(t), "{t}");
        }
    }
}

//! The reference's session-scoped signed claims and bounded initial-request window.

use super::SessionManager;
use crate::auth::types::current_time_ms;
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const IDLE_MS: u64 = 30 * 60 * 1000;
const MAX_MESSAGE_NONCES: usize = 100_000;
const MAX_INITIAL_NONCES: usize = 100_000;
const MAX_INITIAL_PER_IDENTITY: usize = 256;

#[derive(Debug, Default)]
pub(super) struct NonceClaims {
    messages: HashMap<String, HashSet<String>>,
    initial: HashMap<(String, String), u64>,
    // Ordered IDs preserve insertion order even when a clock repeats or goes backwards.
    initial_order: BTreeMap<u64, (String, String, u64)>,
    initial_by_identity: HashMap<String, BTreeSet<u64>>,
    next_id: u64,
}

impl SessionManager {
    /// Claims a signed message nonce once for an active session (#362).
    ///
    /// Returns false on replay. The reference's 100,000-claim capacity fails
    /// closed; removal or 30 minutes of session inactivity discards its claims.
    ///
    /// # Errors
    /// Returns an error for an empty argument, a missing or expired session,
    /// or a new nonce when the session's claim store is full.
    pub fn claim_message_nonce(&mut self, session_nonce: &str, nonce: &str) -> Result<bool> {
        require_nonempty(session_nonce, "sessionNonce")?;
        require_nonempty(nonce, "messageNonce")?;
        if self
            .session_nonce_to_session
            .get(session_nonce)
            .is_some_and(|s| current_time_ms().saturating_sub(s.last_update) >= IDLE_MS)
        {
            self.remove_by_nonce(session_nonce);
        }
        if !self.session_nonce_to_session.contains_key(session_nonce) {
            return Err(Error::AuthError(format!(
                "Session not found for nonce: {session_nonce}"
            )));
        }
        self.nonce_claims.claim_message(session_nonce, nonce)
    }

    /// Claims an unsigned initial request for its claimed identity (#362).
    ///
    /// Claims last 30 minutes, with oldest-first eviction at 256 per identity
    /// or 100,000 overall, independently of session removal.
    ///
    /// # Errors
    /// Returns an error if the identity or initial nonce is empty.
    pub fn claim_initial_request_nonce(&mut self, identity: &str, nonce: &str) -> Result<bool> {
        require_nonempty(identity, "identityKey")?;
        require_nonempty(nonce, "initialNonce")?;
        Ok(self
            .nonce_claims
            .claim_initial(identity, nonce, current_time_ms()))
    }
}

fn require_nonempty(value: &str, name: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::AuthError(format!(
            "{name} must be a non-empty string"
        )));
    }
    Ok(())
}

impl NonceClaims {
    fn claim_message(&mut self, session: &str, nonce: &str) -> Result<bool> {
        let used = self.messages.entry(session.to_owned()).or_default();
        if used.contains(nonce) {
            return Ok(false);
        }
        if used.len() >= MAX_MESSAGE_NONCES {
            return Err(Error::AuthError(
                "BRC-103 session message nonce capacity exhausted".into(),
            ));
        }
        used.insert(nonce.to_owned());
        Ok(true)
    }

    fn claim_initial(&mut self, identity: &str, nonce: &str, now: u64) -> bool {
        let key = (identity.to_owned(), nonce.to_owned());
        if let Some(id) = self.initial.get(&key).copied() {
            if self
                .initial_order
                .get(&id)
                .is_some_and(|(_, _, at)| now.saturating_sub(*at) < IDLE_MS)
            {
                return false;
            }
            self.remove_initial(id);
        }
        if let Some(ids) = self.initial_by_identity.get(identity) {
            if ids.len() >= MAX_INITIAL_PER_IDENTITY {
                if let Some(id) = ids.first().copied() {
                    self.remove_initial(id);
                }
            }
        }
        if self.initial.len() >= MAX_INITIAL_NONCES {
            if let Some((&id, _)) = self.initial_order.first_key_value() {
                self.remove_initial(id);
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        self.initial.insert(key.clone(), id);
        self.initial_order.insert(id, (key.0, key.1, now));
        self.initial_by_identity
            .entry(identity.to_owned())
            .or_default()
            .insert(id);
        true
    }

    fn remove_initial(&mut self, id: u64) {
        if let Some((identity, nonce, _)) = self.initial_order.remove(&id) {
            self.initial.remove(&(identity.clone(), nonce));
            if let Some(ids) = self.initial_by_identity.get_mut(&identity) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.initial_by_identity.remove(&identity);
                }
            }
        }
    }

    pub(super) fn remove_session(&mut self, nonce: &str) {
        self.messages.remove(nonce);
    }

    pub(super) fn prune_initial(&mut self, now: u64) {
        let expired: Vec<_> = self
            .initial_order
            .iter()
            .filter(|(_, (_, _, at))| now.saturating_sub(*at) >= IDLE_MS)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            self.remove_initial(id);
        }
    }
}

#[cfg(test)]
#[path = "session_nonces_tests.rs"]
mod tests;

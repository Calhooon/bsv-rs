//! Session management for concurrent peer sessions.
//!
//! The `SessionManager` handles multiple concurrent sessions per peer identity,
//! using dual indexing by session nonce (unique) and identity key (multiple per peer).

use crate::auth::types::PeerSession;
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};

/// Manages multiple concurrent sessions per peer identity.
///
/// Sessions are indexed by both session nonce (unique) and
/// identity key (multiple sessions per identity allowed).
///
/// # Session Lookup
///
/// When looking up a session by identifier:
/// 1. First tries to match as a session nonce (exact match)
/// 2. If not found, tries as an identity key (returns "best" session)
///
/// The "best" session is selected by:
/// 1. Prefer authenticated sessions over unauthenticated
/// 2. Among same auth status, prefer most recently updated
#[derive(Debug, Default)]
pub struct SessionManager {
    /// Primary index: session_nonce -> session
    session_nonce_to_session: HashMap<String, PeerSession>,
    /// Secondary index: identity_key_hex -> set of session_nonces
    identity_key_to_nonces: HashMap<String, HashSet<String>>,
}

impl SessionManager {
    /// Creates a new session manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a new session to the manager.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session has no nonce
    /// - A session with the same nonce already exists
    pub fn add_session(&mut self, session: PeerSession) -> Result<()> {
        let nonce = session
            .session_nonce
            .as_ref()
            .ok_or_else(|| Error::AuthError("Session must have a nonce".into()))?;

        if self.session_nonce_to_session.contains_key(nonce) {
            return Err(Error::AuthError(format!(
                "Session nonce already exists: {}",
                nonce
            )));
        }

        // Add to secondary index if identity key exists
        if let Some(ref identity_key) = session.peer_identity_key {
            let key_hex = identity_key.to_hex();
            self.identity_key_to_nonces
                .entry(key_hex)
                .or_default()
                .insert(nonce.clone());
        }

        self.session_nonce_to_session.insert(nonce.clone(), session);
        Ok(())
    }

    /// Updates an existing session.
    ///
    /// If the session's nonce doesn't exist in the manager, this is a no-op.
    /// If the identity key changed, updates the secondary index.
    pub fn update_session(&mut self, session: PeerSession) {
        if let Some(ref nonce) = session.session_nonce {
            // Check if session exists
            if let Some(old_session) = self.session_nonce_to_session.get(nonce) {
                // Handle identity key change in secondary index
                let old_key_hex = old_session.peer_identity_key.as_ref().map(|k| k.to_hex());
                let new_key_hex = session.peer_identity_key.as_ref().map(|k| k.to_hex());

                if old_key_hex != new_key_hex {
                    // Remove from old identity key index
                    if let Some(old_hex) = old_key_hex {
                        if let Some(nonces) = self.identity_key_to_nonces.get_mut(&old_hex) {
                            nonces.remove(nonce);
                            if nonces.is_empty() {
                                self.identity_key_to_nonces.remove(&old_hex);
                            }
                        }
                    }

                    // Add to new identity key index
                    if let Some(new_hex) = new_key_hex {
                        self.identity_key_to_nonces
                            .entry(new_hex)
                            .or_default()
                            .insert(nonce.clone());
                    }
                }

                // Update the session
                self.session_nonce_to_session.insert(nonce.clone(), session);
            }
        }
    }

    /// Gets a session by nonce or identity key.
    ///
    /// If the identifier matches a session nonce, returns that session.
    /// If it matches an identity key, returns the "best" session for that peer
    /// (most recent authenticated session, or most recent unauthenticated).
    pub fn get_session(&self, identifier: &str) -> Option<&PeerSession> {
        // First, try as session nonce
        if let Some(session) = self.session_nonce_to_session.get(identifier) {
            return Some(session);
        }

        // Then, try as identity key
        if let Some(nonces) = self.identity_key_to_nonces.get(identifier) {
            return self.select_best_session(nonces);
        }

        None
    }

    /// Gets a mutable session by session nonce.
    pub fn get_session_mut(&mut self, session_nonce: &str) -> Option<&mut PeerSession> {
        self.session_nonce_to_session.get_mut(session_nonce)
    }

    /// Removes a session from the manager.
    pub fn remove_session(&mut self, session: &PeerSession) {
        if let Some(ref nonce) = session.session_nonce {
            self.session_nonce_to_session.remove(nonce);

            // Remove from secondary index
            if let Some(ref identity_key) = session.peer_identity_key {
                let key_hex = identity_key.to_hex();
                if let Some(nonces) = self.identity_key_to_nonces.get_mut(&key_hex) {
                    nonces.remove(nonce);
                    if nonces.is_empty() {
                        self.identity_key_to_nonces.remove(&key_hex);
                    }
                }
            }
        }
    }

    /// Removes a session by its nonce.
    pub fn remove_by_nonce(&mut self, session_nonce: &str) {
        if let Some(session) = self.session_nonce_to_session.remove(session_nonce) {
            // Remove from secondary index
            if let Some(ref identity_key) = session.peer_identity_key {
                let key_hex = identity_key.to_hex();
                if let Some(nonces) = self.identity_key_to_nonces.get_mut(&key_hex) {
                    nonces.remove(session_nonce);
                    if nonces.is_empty() {
                        self.identity_key_to_nonces.remove(&key_hex);
                    }
                }
            }
        }
    }

    /// Checks if a session exists for the given identifier.
    pub fn has_session(&self, identifier: &str) -> bool {
        self.get_session(identifier).is_some()
    }

    /// Returns the number of sessions.
    pub fn len(&self) -> usize {
        self.session_nonce_to_session.len()
    }

    /// Returns true if there are no sessions.
    pub fn is_empty(&self) -> bool {
        self.session_nonce_to_session.is_empty()
    }

    /// Gets all sessions for an identity key.
    pub fn get_sessions_for_identity(&self, identity_key_hex: &str) -> Vec<&PeerSession> {
        self.identity_key_to_nonces
            .get(identity_key_hex)
            .map(|nonces| {
                nonces
                    .iter()
                    .filter_map(|n| self.session_nonce_to_session.get(n))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns an iterator over all sessions.
    pub fn iter(&self) -> impl Iterator<Item = &PeerSession> {
        self.session_nonce_to_session.values()
    }

    /// Clears all sessions.
    pub fn clear(&mut self) {
        self.session_nonce_to_session.clear();
        self.identity_key_to_nonces.clear();
    }

    /// Selects the "best" session from a set of nonces.
    ///
    /// Prefers authenticated sessions, then most recently updated.
    fn select_best_session(&self, nonces: &HashSet<String>) -> Option<&PeerSession> {
        let mut best: Option<&PeerSession> = None;

        for nonce in nonces {
            if let Some(session) = self.session_nonce_to_session.get(nonce) {
                best = match best {
                    None => Some(session),
                    Some(current) => {
                        // Prefer authenticated over unauthenticated
                        if session.is_authenticated && !current.is_authenticated {
                            Some(session)
                        } else if !session.is_authenticated && current.is_authenticated {
                            Some(current)
                        } else if session.last_update > current.last_update {
                            // Same auth status: prefer more recent
                            Some(session)
                        } else {
                            Some(current)
                        }
                    }
                };
            }
        }

        best
    }

    /// Removes sessions that haven't been updated in the given duration.
    ///
    /// Returns the number of sessions removed.
    pub fn prune_stale_sessions(&mut self, max_age_ms: u64) -> usize {
        let now = crate::auth::types::current_time_ms();
        let cutoff = now.saturating_sub(max_age_ms);

        let stale_nonces: Vec<String> = self
            .session_nonce_to_session
            .iter()
            .filter(|(_, session)| session.last_update < cutoff)
            .map(|(nonce, _)| nonce.clone())
            .collect();

        let count = stale_nonces.len();
        for nonce in stale_nonces {
            self.remove_by_nonce(&nonce);
        }

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::current_time_ms;
    use crate::primitives::PrivateKey;

    fn make_session(
        nonce: &str,
        identity_key: Option<&crate::primitives::PublicKey>,
    ) -> PeerSession {
        PeerSession {
            session_nonce: Some(nonce.to_string()),
            peer_identity_key: identity_key.cloned(),
            last_update: current_time_ms(),
            ..Default::default()
        }
    }

    #[test]
    fn test_add_and_get_session() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        let session = make_session("nonce123", Some(&key));
        mgr.add_session(session).unwrap();

        // Find by nonce
        assert!(mgr.get_session("nonce123").is_some());

        // Find by identity key
        assert!(mgr.get_session(&key.to_hex()).is_some());

        // Not found
        assert!(mgr.get_session("nonexistent").is_none());
    }

    #[test]
    fn test_duplicate_nonce_rejected() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        let session1 = make_session("nonce123", Some(&key));
        let session2 = make_session("nonce123", Some(&key));

        mgr.add_session(session1).unwrap();
        assert!(mgr.add_session(session2).is_err());
    }

    #[test]
    fn test_session_without_nonce_rejected() {
        let mut mgr = SessionManager::new();
        let session = PeerSession::new();
        assert!(mgr.add_session(session).is_err());
    }

    #[test]
    fn test_prefers_authenticated() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        // Add unauthenticated session (newer)
        let mut s1 = make_session("nonce1", Some(&key));
        s1.is_authenticated = false;
        s1.last_update = current_time_ms() + 1000;
        mgr.add_session(s1).unwrap();

        // Add authenticated session (older)
        let mut s2 = make_session("nonce2", Some(&key));
        s2.is_authenticated = true;
        s2.last_update = current_time_ms();
        mgr.add_session(s2).unwrap();

        // Should prefer authenticated even though older
        let session = mgr.get_session(&key.to_hex()).unwrap();
        assert!(session.is_authenticated);
        assert_eq!(session.session_nonce.as_deref(), Some("nonce2"));
    }

    #[test]
    fn test_prefers_newer_when_same_auth_status() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        // Add older session
        let mut s1 = make_session("nonce1", Some(&key));
        s1.is_authenticated = true;
        s1.last_update = current_time_ms();
        mgr.add_session(s1).unwrap();

        // Add newer session
        let mut s2 = make_session("nonce2", Some(&key));
        s2.is_authenticated = true;
        s2.last_update = current_time_ms() + 1000;
        mgr.add_session(s2).unwrap();

        // Should prefer newer
        let session = mgr.get_session(&key.to_hex()).unwrap();
        assert_eq!(session.session_nonce.as_deref(), Some("nonce2"));
    }

    #[test]
    fn test_update_session() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        let session = make_session("nonce123", Some(&key));
        mgr.add_session(session).unwrap();

        // Update authentication status
        let mut updated = mgr.get_session("nonce123").unwrap().clone();
        updated.is_authenticated = true;
        mgr.update_session(updated);

        let session = mgr.get_session("nonce123").unwrap();
        assert!(session.is_authenticated);
    }

    #[test]
    fn test_remove_session() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        let session = make_session("nonce123", Some(&key));
        mgr.add_session(session.clone()).unwrap();
        assert!(mgr.has_session("nonce123"));
        assert!(mgr.has_session(&key.to_hex()));

        mgr.remove_session(&session);
        assert!(!mgr.has_session("nonce123"));
        assert!(!mgr.has_session(&key.to_hex()));
    }

    #[test]
    fn test_remove_by_nonce() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        let session = make_session("nonce123", Some(&key));
        mgr.add_session(session).unwrap();

        mgr.remove_by_nonce("nonce123");
        assert!(!mgr.has_session("nonce123"));
    }

    #[test]
    fn test_multiple_sessions_per_identity() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        let s1 = make_session("nonce1", Some(&key));
        let s2 = make_session("nonce2", Some(&key));
        let s3 = make_session("nonce3", Some(&key));

        mgr.add_session(s1).unwrap();
        mgr.add_session(s2).unwrap();
        mgr.add_session(s3).unwrap();

        let sessions = mgr.get_sessions_for_identity(&key.to_hex());
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut mgr = SessionManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);

        let session = make_session("nonce123", None);
        mgr.add_session(session).unwrap();
        assert!(!mgr.is_empty());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut mgr = SessionManager::new();
        let key = PrivateKey::random().public_key();

        mgr.add_session(make_session("nonce1", Some(&key))).unwrap();
        mgr.add_session(make_session("nonce2", Some(&key))).unwrap();

        assert_eq!(mgr.len(), 2);
        mgr.clear();
        assert!(mgr.is_empty());
    }
}

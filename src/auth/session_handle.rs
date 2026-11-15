//! The handle `Peer::session_manager` hands out (#843dforeign).

use super::SessionManager;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A shared [`SessionManager`]: the type [`Peer::session_manager`] hands out,
/// this crate's own (#843dforeign), so no public signature names another
/// crate's lock and a `tokio` major is never this crate's break.
///
/// A clone shares the same store. [`read`] waits for shared access and
/// [`write`] for exclusive access; each answers a guard that dereferences to
/// the [`SessionManager`], whose doors are reached by name through it
/// (`add_session`, `update_session`, `get_session`, `remove_session`,
/// `has_session`). A guard is released when it is dropped; holding one across
/// a call into the [`Peer`] that owns the store waits on itself.
///
/// The reference's `Peer` exposes the store itself as a public property
/// (`ts-stack@edf6e03` `Peer.ts:55`, `:163`), which a single-threaded runtime
/// can do; here the store is shared between tasks, so the door is a handle.
/// `Debug` prints no session.
///
/// A binding typed by the lock this door returned until #843dforeign no longer
/// compiles:
///
/// ```compile_fail,E0308
/// use bsv_rs::auth::{MockTransport, Peer, PeerOptions, SessionManager};
/// use bsv_rs::wallet::ProtoWallet;
/// use std::sync::Arc;
///
/// let peer = Peer::new(PeerOptions::new(ProtoWallet::new(None), MockTransport::new()));
/// let _: &Arc<tokio::sync::RwLock<SessionManager>> = peer.session_manager();
/// ```
///
/// [`Peer`]: crate::auth::Peer
/// [`Peer::session_manager`]: crate::auth::Peer::session_manager
/// [`read`]: SessionManagerHandle::read
/// [`write`]: SessionManagerHandle::write
#[derive(Clone)]
pub struct SessionManagerHandle {
    inner: Arc<RwLock<SessionManager>>,
}

impl SessionManagerHandle {
    pub(crate) fn new(manager: SessionManager) -> Self {
        Self {
            inner: Arc::new(RwLock::new(manager)),
        }
    }

    /// Shared access to the store, waiting while a writer holds it.
    pub async fn read(&self) -> SessionManagerReadGuard<'_> {
        SessionManagerReadGuard {
            inner: self.inner.read().await,
        }
    }

    /// Exclusive access to the store, waiting while any guard holds it.
    pub async fn write(&self) -> SessionManagerWriteGuard<'_> {
        SessionManagerWriteGuard {
            inner: self.inner.write().await,
        }
    }
}

impl std::fmt::Debug for SessionManagerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManagerHandle")
            .finish_non_exhaustive()
    }
}

/// Shared access to a [`SessionManager`], from [`SessionManagerHandle::read`];
/// released on drop. `Debug` prints no session.
pub struct SessionManagerReadGuard<'a> {
    inner: RwLockReadGuard<'a, SessionManager>,
}

impl Deref for SessionManagerReadGuard<'_> {
    type Target = SessionManager;

    fn deref(&self) -> &SessionManager {
        &self.inner
    }
}

impl std::fmt::Debug for SessionManagerReadGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManagerReadGuard")
            .finish_non_exhaustive()
    }
}

/// Exclusive access to a [`SessionManager`], from
/// [`SessionManagerHandle::write`]; released on drop. `Debug` prints no
/// session.
pub struct SessionManagerWriteGuard<'a> {
    inner: RwLockWriteGuard<'a, SessionManager>,
}

impl Deref for SessionManagerWriteGuard<'_> {
    type Target = SessionManager;

    fn deref(&self) -> &SessionManager {
        &self.inner
    }
}

impl DerefMut for SessionManagerWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut SessionManager {
        &mut self.inner
    }
}

impl std::fmt::Debug for SessionManagerWriteGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManagerWriteGuard")
            .finish_non_exhaustive()
    }
}

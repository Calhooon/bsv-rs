//! Store configuration mapped to the reference's createAction options (#342).
use super::types::KVStoreConfig;
use crate::wallet::CreateActionOptions;

impl Default for KVStoreConfig {
    fn default() -> Self {
        Self {
            protocol_id: "kvstore".to_string(),
            service_name: "ls_kvstore".to_string(),
            token_amount: 1,
            topics: vec!["tm_kvstore".to_string()],
            originator: None,
            encrypt: true,
            accept_delayed_broadcast: false,
            overlay_broadcast: false,
        }
    }
}

impl KVStoreConfig {
    /// Sets acceptance of delayed wallet broadcasts (default: false).
    #[must_use]
    pub fn with_accept_delayed_broadcast(mut self, accept: bool) -> Self {
        self.accept_delayed_broadcast = accept;
        self
    }

    /// Sets the global store's `noSend` option (default: false).
    #[must_use]
    pub fn with_overlay_broadcast(mut self, enabled: bool) -> Self {
        self.overlay_broadcast = enabled;
        self
    }

    pub(crate) fn action_options(&self, global: bool, removal: bool) -> CreateActionOptions {
        CreateActionOptions {
            accept_delayed_broadcast: Some(self.accept_delayed_broadcast),
            no_send: global.then_some(self.overlay_broadcast),
            randomize_outputs: (global || !removal).then_some(false),
            ..Default::default()
        }
    }
}

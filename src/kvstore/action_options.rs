//! Private store configuration mapped to the reference's createAction options (#342).
use crate::wallet::CreateActionOptions;

// Keep these options off KVStoreConfig so existing exhaustive literals still compile.
#[derive(Debug, Default)]
pub(super) struct ActionOptions {
    pub(super) accept_delayed_broadcast: bool,
    pub(super) no_send: bool,
}

impl ActionOptions {
    pub(super) fn for_action(&self, global: bool, removal: bool) -> CreateActionOptions {
        CreateActionOptions {
            accept_delayed_broadcast: Some(self.accept_delayed_broadcast),
            no_send: global.then_some(self.no_send),
            randomize_outputs: (global || !removal).then_some(false),
            ..Default::default()
        }
    }
}

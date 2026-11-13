/// #904's fold: the name the counting wallet (`identity_reveal_wallet.rs`)
/// records for a wallet call, the method's own identifier, resolved through
/// `WalletInterface` alone (`<W as WalletInterface>::name`, the third fold):
/// a name that is no method of that trait does not compile, whatever other
/// trait could name it (`wallet_call!(from)` is E0576, where `W::from`
/// found `From::from` and compiled until the third fold; `signAction` is
/// E0576 too). Every name the double records and every call name the
/// `contacts_*` and `identity_*` tests assert on goes through it, so such an
/// assertion cannot look for a name the double never records
/// (`pushdrop_lock_key_order_816.rs` asserts on literal names). Included by the double
/// and by the crate's doc tests (`src/lib.rs`, `WalletCallMacroDocTests`),
/// which hold both refusals and one acceptance.
macro_rules! wallet_call {
    ($method:ident) => {{
        #[allow(dead_code)]
        fn named<W: bsv_rs::wallet::WalletInterface>() {
            let _ = <W as bsv_rs::wallet::WalletInterface>::$method;
        }
        stringify!($method)
    }};
}

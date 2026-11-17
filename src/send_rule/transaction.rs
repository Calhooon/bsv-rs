//! The `transaction` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::transaction::{
    verify_stream_async, AsyncByteSource, AsyncStreamVerifier, Broadcaster, ChainTracker,
    LivePolicy, MerklePath, Transaction,
};
use core::future::Future;

// src/transaction/broadcaster.rs
fn broadcaster<V: Values, B: Broadcaster + ?Sized>(v: &V) {
    let broadcaster = v.any::<&B>();
    send(broadcaster.broadcast(v.any()));
    send(broadcaster.broadcast_many(v.any()));
}

// src/transaction/chain_tracker.rs
fn chain_tracker<V: Values, C: ChainTracker + ?Sized>(v: &V) {
    let tracker = v.any::<&C>();
    send(tracker.is_valid_root_for_height(v.any(), v.any()));
    send(tracker.current_height());
    send(tracker.mining_tip());
}

// src/transaction/transaction.rs
fn transaction<V: Values>(v: &V) {
    let building = v.any::<&mut Transaction>();
    send(building.sign());
    let building = v.any::<&mut Transaction>();
    send(building.fee(v.any(), v.any()));
    let tx = v.any::<&Transaction>();
    send(tx.verify(v.any(), v.any(), v.any()));
}

// src/transaction/verify.rs
fn verify<V: Values>(v: &V) {
    let tx = v.any::<&Transaction>();
    send(tx.verify_with_chain_params(v.any(), v.any(), v.any(), v.any()));
    send(tx.verify_with_work_budget(v.any(), v.any(), v.any(), v.any()));
    send(tx.verify_with_chain_params_and_work_budget(v.any(), v.any(), v.any(), v.any(), v.any()));
    send(tx.verify_with_work_budgets(v.any(), v.any(), v.any(), v.any()));
    send(tx.verify_with_chain_params_and_work_budgets(v.any(), v.any(), v.any(), v.any(), v.any()));
}

// src/transaction/merkle_path_verify.rs
fn merkle_path<V: Values>(v: &V) {
    let path = v.any::<&MerklePath>();
    send(path.verify(v.any(), v.any()));
}

// src/transaction/fee_models/live_policy.rs
fn live_policy<V: Values>(v: &V) {
    let policy = v.any::<&LivePolicy>();
    send(policy.refresh());
}

/// A source whose chunks come from a `Send` future: the stream's two doors
/// name no bound on the source's future, so theirs is `Send` when it is.
struct SendSource;

impl AsyncByteSource for SendSource {
    fn next_chunk(&mut self) -> impl Future<Output = std::io::Result<Option<Vec<u8>>>> {
        core::future::ready(Ok(None))
    }
}

// src/transaction/beef_stream.rs
fn beef_stream<V: Values>(v: &V) {
    let reader = v.any::<&mut AsyncStreamVerifier>();
    send(reader.run(v.any::<&mut SendSource>(), v.any()));
    send(verify_stream_async(
        v.any::<&mut SendSource>(),
        v.any(),
        v.any(),
    ));
}

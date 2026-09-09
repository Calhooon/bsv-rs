//! The overlay network: a SLAP lookup and a SHIP broadcast.
//!
//! Compiled by `cargo build --example overlay --features "overlay,http"`; running
//! it reaches the public overlay hosts of the mainnet preset.
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, TopicBroadcaster,
    TopicBroadcasterConfig,
};
use bsv_rs::transaction::Transaction;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Lookup: the resolver discovers competent hosts for the service through
    // the SLAP trackers (cached, coalesced across concurrent askers, backed
    // off per host by its reputation) and fans the question out.
    let resolver = LookupResolver::new(LookupResolverConfig::default());
    let question = LookupQuestion::new("ls_kvstore", serde_json::json!({ "key": "hello" }));
    match resolver.query(&question, Some(5_000)).await {
        Ok(LookupAnswer::OutputList { outputs }) => {
            println!("lookup answered {} output(s)", outputs.len())
        }
        Ok(other) => println!("lookup answered a {:?} shape", other.answer_type()),
        Err(e) => println!("lookup failed: {e}"),
    }

    // Broadcast: the transaction rides SHIP to every host advertising the
    // topic, as a BEEF; the answer is a STEAK per topic naming what each host
    // admitted.
    let broadcaster = TopicBroadcaster::new(
        vec!["tm_kvstore".to_string()],
        TopicBroadcasterConfig::default(),
    )
    .unwrap();
    let tx = Transaction::new();
    match broadcaster.broadcast_tx(&tx).await {
        Ok(steak) => println!("broadcast acknowledged: {steak:?}"),
        Err(e) => println!("broadcast refused: {e:?}"),
    }
}

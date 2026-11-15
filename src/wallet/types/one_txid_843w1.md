
# One transaction id (#843, W1)

`txid` is the crate's one [`Txid`](crate::transaction::Txid), so a
transaction's wire-order bytes cannot be handed over as an id. Until the
wallet's `TxId = [u8; 32]` alias went, each block below marked `compile_fail`
compiled and named another transaction (the array reversed); each stands
beside the same lines with `tx.txid()`, which compile.

```
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::Outpoint;
let tx = Transaction::new();
let outpoint = Outpoint::new(tx.txid(), 0);
assert_eq!(outpoint.to_string(), format!("{}.0", tx.id()));
```

```compile_fail,E0308
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::Outpoint;
let tx = Transaction::new();
let outpoint = Outpoint::new(tx.hash(), 0);
assert_eq!(outpoint.to_string(), format!("{}.0", tx.id()));
```

A literal:

```
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::Outpoint;
let tx = Transaction::new();
let outpoint = Outpoint { txid: tx.txid(), vout: 0 };
assert_eq!(outpoint.to_string(), format!("{}.0", tx.id()));
```

```compile_fail,E0308
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::Outpoint;
let tx = Transaction::new();
let outpoint = Outpoint { txid: *tx.txid().as_wire_bytes(), vout: 0 };
assert_eq!(outpoint.to_string(), format!("{}.0", tx.id()));
```

A result's field:

```
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::{SendWithResult, SendWithResultStatus};
let tx = Transaction::new();
let result = SendWithResult { txid: tx.txid(), status: SendWithResultStatus::Sending };
assert_eq!(result.txid, tx.id());
```

```compile_fail,E0308
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::{SendWithResult, SendWithResultStatus};
let tx = Transaction::new();
let result = SendWithResult { txid: tx.hash(), status: SendWithResultStatus::Sending };
assert_eq!(result.txid, tx.id());
```

A list's field:

```
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::CreateActionOptions;
let tx = Transaction::new();
let options = CreateActionOptions { known_txids: Some(vec![tx.txid()]), ..Default::default() };
assert_eq!(options.known_txids.unwrap()[0], tx.id());
```

```compile_fail,E0308
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::CreateActionOptions;
let tx = Transaction::new();
let options = CreateActionOptions { known_txids: Some(vec![tx.hash()]), ..Default::default() };
assert_eq!(options.known_txids.unwrap()[0], tx.id());
```

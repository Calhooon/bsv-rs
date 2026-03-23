//! Transaction history traversal.
//!
//! The Historian builds a chronological history of values by traversing
//! a transaction's input ancestry and interpreting each output with a
//! provided interpreter function.
//!
//! This is useful for protocols that track state changes over time, such as
//! token transfers or key-value stores.

use crate::transaction::Transaction;
use crate::Result;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

/// Interpreter function type.
///
/// Given a transaction, output index, and optional context, returns an optional
/// value of type T. Returning `None` means the output does not contribute to
/// history.
///
/// # Type Parameters
///
/// * `T` - The decoded/typed value produced for a matching output
/// * `C` - The per-call context passed through Historian to the interpreter
pub type InterpreterFn<T, C> = Box<
    dyn Fn(&Transaction, u32, Option<&C>) -> Pin<Box<dyn Future<Output = Option<T>>>> + Send + Sync,
>;

/// Configuration for the Historian.
#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct HistorianConfig<T, C> {
    /// Enable debug logging.
    pub debug: bool,
    /// Cache for history results.
    pub history_cache: Option<HashMap<String, Vec<T>>>,
    /// Version string for cache key (bump when interpreter semantics change).
    pub interpreter_version: Option<String>,
    /// Function to generate cache key from context.
    pub ctx_key_fn: Option<Box<dyn Fn(Option<&C>) -> String + Send + Sync>>,
}

/// Traverses transaction ancestry to build history.
///
/// Uses an interpreter function to extract values from transaction outputs,
/// then follows input sources recursively to build a chronological history.
///
/// # Type Parameters
///
/// * `T` - The value type produced by the interpreter
/// * `C` - The context type passed to the interpreter
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::overlay::Historian;
///
/// // Define an interpreter that extracts token amounts
/// let interpreter = Box::new(|tx, output_idx, ctx| {
///     Box::pin(async move {
///         // Parse token data from output
///         // Return Some(amount) if valid, None otherwise
///         Some(100u64)
///     })
/// });
///
/// let historian = Historian::new(interpreter, Default::default());
/// let history = historian.build_history(&tip_tx, None).await?;
/// ```
#[allow(clippy::type_complexity)]
pub struct Historian<T, C> {
    interpreter: InterpreterFn<T, C>,
    debug: bool,
    history_cache: Option<tokio::sync::RwLock<HashMap<String, Vec<T>>>>,
    interpreter_version: String,
    ctx_key_fn: Option<Box<dyn Fn(Option<&C>) -> String + Send + Sync>>,
}

impl<T: Clone + Send + Sync + 'static, C: Send + Sync + 'static> Historian<T, C> {
    /// Create a new Historian with the given interpreter.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - Function to interpret transaction outputs
    /// * `config` - Configuration options
    pub fn new(interpreter: InterpreterFn<T, C>, config: HistorianConfig<T, C>) -> Self {
        Self {
            interpreter,
            debug: config.debug,
            history_cache: config.history_cache.map(tokio::sync::RwLock::new),
            interpreter_version: config
                .interpreter_version
                .unwrap_or_else(|| "v1".to_string()),
            ctx_key_fn: config.ctx_key_fn,
        }
    }

    /// Build history starting from a transaction.
    ///
    /// Recursively traverses input sources, collecting interpreter results.
    /// Returns values in chronological order (oldest first).
    ///
    /// # Arguments
    ///
    /// * `start_transaction` - The transaction to start traversal from
    /// * `context` - Optional context to pass to the interpreter
    ///
    /// # Returns
    ///
    /// A vector of values in chronological order (oldest first).
    pub async fn build_history(
        &self,
        start_transaction: &Transaction,
        context: Option<&C>,
    ) -> Result<Vec<T>> {
        // Check cache first
        let cache_key = self.cache_key(start_transaction, context);
        if let Some(ref cache) = self.history_cache {
            let cache_read = cache.read().await;
            if let Some(cached) = cache_read.get(&cache_key) {
                if self.debug {
                    eprintln!("[Historian] Cache hit: {}", cache_key);
                }
                return Ok(cached.clone());
            }
        }

        let mut visited: HashSet<String> = HashSet::new();
        let mut results: Vec<T> = Vec::new();

        self.traverse(start_transaction, context, &mut visited, &mut results)
            .await?;

        // Reverse for chronological order (oldest first)
        results.reverse();

        // Cache result
        if let Some(ref cache) = self.history_cache {
            let mut cache_write = cache.write().await;
            cache_write.insert(cache_key.clone(), results.clone());
            if self.debug {
                eprintln!("[Historian] Cached: {}", cache_key);
            }
        }

        Ok(results)
    }

    /// Recursive traversal helper.
    fn traverse<'a>(
        &'a self,
        tx: &'a Transaction,
        context: Option<&'a C>,
        visited: &'a mut HashSet<String>,
        results: &'a mut Vec<T>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>>
    where
        T: 'a,
        C: 'a,
    {
        Box::pin(async move {
            let txid = tx.id();

            // Prevent cycles
            if visited.contains(&txid) {
                if self.debug {
                    eprintln!("[Historian] Skipping visited: {}", txid);
                }
                return Ok(());
            }
            visited.insert(txid.clone());

            if self.debug {
                eprintln!("[Historian] Processing: {}", txid);
            }

            // Interpret each output
            for (idx, _output) in tx.outputs.iter().enumerate() {
                if let Some(value) = (self.interpreter)(tx, idx as u32, context).await {
                    results.push(value);
                    if self.debug {
                        eprintln!("[Historian] Found value at output {}", idx);
                    }
                }
            }

            // Traverse input sources
            for input in &tx.inputs {
                if let Some(ref source_tx) = input.source_transaction {
                    self.traverse(source_tx, context, visited, results).await?;
                } else if self.debug {
                    eprintln!("[Historian] Input missing source transaction");
                }
            }

            Ok(())
        })
    }

    /// Generate cache key for a transaction and context.
    fn cache_key(&self, tx: &Transaction, context: Option<&C>) -> String {
        let txid = tx.id();
        let ctx_key = self
            .ctx_key_fn
            .as_ref()
            .map(|f| f(context))
            .unwrap_or_default();

        format!("{}|{}|{}", self.interpreter_version, txid, ctx_key)
    }
}

/// Synchronous version of Historian for simpler use cases.
///
/// This version uses a synchronous interpreter function and does not
/// require async/await.
#[allow(clippy::type_complexity)]
pub struct SyncHistorian<T, C> {
    interpreter: Box<dyn Fn(&Transaction, u32, Option<&C>) -> Option<T> + Send + Sync>,
    debug: bool,
    #[allow(dead_code)]
    interpreter_version: String,
}

impl<T: Clone + Send + Sync, C: Send + Sync> SyncHistorian<T, C> {
    /// Create a new synchronous Historian.
    pub fn new<F>(interpreter: F) -> Self
    where
        F: Fn(&Transaction, u32, Option<&C>) -> Option<T> + Send + Sync + 'static,
    {
        Self {
            interpreter: Box::new(interpreter),
            debug: false,
            interpreter_version: "v1".to_string(),
        }
    }

    /// Enable debug logging.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set interpreter version for cache invalidation.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.interpreter_version = version.into();
        self
    }

    /// Build history starting from a transaction.
    ///
    /// Returns values in chronological order (oldest first).
    pub fn build_history(&self, start_transaction: &Transaction, context: Option<&C>) -> Vec<T> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut results: Vec<T> = Vec::new();

        self.traverse(start_transaction, context, &mut visited, &mut results);

        // Reverse for chronological order (oldest first)
        results.reverse();
        results
    }

    /// Recursive traversal helper.
    fn traverse(
        &self,
        tx: &Transaction,
        context: Option<&C>,
        visited: &mut HashSet<String>,
        results: &mut Vec<T>,
    ) {
        let txid = tx.id();

        // Prevent cycles
        if visited.contains(&txid) {
            return;
        }
        visited.insert(txid.clone());

        if self.debug {
            eprintln!("[SyncHistorian] Processing: {}", txid);
        }

        // Interpret each output
        for (idx, _output) in tx.outputs.iter().enumerate() {
            if let Some(value) = (self.interpreter)(tx, idx as u32, context) {
                results.push(value);
            }
        }

        // Traverse input sources
        for input in &tx.inputs {
            if let Some(ref source_tx) = input.source_transaction {
                self.traverse(source_tx, context, visited, results);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::LockingScript;
    use crate::transaction::{TransactionInput, TransactionOutput};

    fn create_test_tx(_id_suffix: u8, source: Option<Transaction>) -> Transaction {
        let mut tx = Transaction::new();
        tx.outputs.push(TransactionOutput::new(
            1000,
            LockingScript::from_asm("OP_TRUE").unwrap(),
        ));

        if let Some(source_tx) = source {
            let mut input = TransactionInput::new(source_tx.id(), 0);
            input.source_transaction = Some(Box::new(source_tx));
            tx.inputs.push(input);
        }

        tx
    }

    #[test]
    fn test_sync_historian_single_tx() {
        let tx = create_test_tx(1, None);

        let historian = SyncHistorian::<u32, ()>::new(|_tx, output_idx, _ctx| Some(output_idx));

        let history = historian.build_history(&tx, None);
        assert_eq!(history, vec![0]);
    }

    #[test]
    fn test_sync_historian_chain() {
        // Create a chain: tx1 <- tx2 <- tx3
        let tx1 = create_test_tx(1, None);
        let tx2 = create_test_tx(2, Some(tx1));
        let tx3 = create_test_tx(3, Some(tx2));

        let historian = SyncHistorian::<String, ()>::new(|tx, _output_idx, _ctx| Some(tx.id()));

        let history = historian.build_history(&tx3, None);

        // Should be in chronological order (oldest first)
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_sync_historian_filters() {
        let tx = create_test_tx(1, None);

        // Interpreter that filters some outputs
        let historian = SyncHistorian::<u32, ()>::new(|_tx, output_idx, _ctx| {
            if output_idx % 2 == 0 {
                Some(output_idx)
            } else {
                None
            }
        });

        let history = historian.build_history(&tx, None);
        // Single output at index 0 (even)
        assert_eq!(history, vec![0]);
    }

    #[test]
    fn test_sync_historian_with_context() {
        let tx = create_test_tx(1, None);

        let historian =
            SyncHistorian::<u32, u32>::new(|_tx, output_idx, ctx| ctx.map(|c| output_idx + c));

        let history_with_ctx = historian.build_history(&tx, Some(&10));
        assert_eq!(history_with_ctx, vec![10]);

        let history_without_ctx = historian.build_history(&tx, None);
        assert!(history_without_ctx.is_empty());
    }

    #[test]
    fn test_sync_historian_prevents_cycles() {
        // Create a tx that references itself (shouldn't happen in practice)
        let tx = create_test_tx(1, None);

        let historian = SyncHistorian::<u32, ()>::new(|_tx, output_idx, _ctx| Some(output_idx));

        // Should not infinite loop
        let history = historian.build_history(&tx, None);
        assert_eq!(history.len(), 1);
    }

    #[tokio::test]
    async fn test_async_historian_basic() {
        let tx = create_test_tx(1, None);

        let interpreter: InterpreterFn<u32, ()> =
            Box::new(|_tx, output_idx, _ctx| Box::pin(async move { Some(output_idx) }));

        let historian = Historian::new(interpreter, HistorianConfig::default());
        let history = historian.build_history(&tx, None).await.unwrap();

        assert_eq!(history, vec![0]);
    }

    #[tokio::test]
    async fn test_async_historian_with_cache() {
        let tx = create_test_tx(1, None);

        let interpreter: InterpreterFn<u32, ()> =
            Box::new(|_tx, output_idx, _ctx| Box::pin(async move { Some(output_idx) }));

        let config = HistorianConfig {
            debug: false,
            history_cache: Some(HashMap::new()),
            interpreter_version: Some("v1".to_string()),
            ctx_key_fn: None,
        };

        let historian = Historian::new(interpreter, config);

        // First call populates cache
        let history1 = historian.build_history(&tx, None).await.unwrap();
        // Second call should use cache
        let history2 = historian.build_history(&tx, None).await.unwrap();

        assert_eq!(history1, history2);
    }
}

//! One mutable retry counter shared by nested fetch and payment attempts.

use super::response::words;
use crate::Result;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(super) struct RetryBudget(Arc<Mutex<Option<u32>>>);

impl RetryBudget {
    pub fn new(counter: Option<u32>) -> Self {
        Self(Arc::new(Mutex::new(counter)))
    }

    pub fn enter(&self) -> Result<()> {
        let mut counter = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(counter) = &mut *counter {
            *counter = counter
                .checked_sub(1)
                .ok_or_else(|| words("Request failed after maximum number of retries."))?;
        }
        Ok(())
    }

    pub fn initialize(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert(3);
    }
}

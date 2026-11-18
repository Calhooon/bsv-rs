//! A BRC-112 balance query, by its basket (#843).
//!
//! The reference's `isBalanceQuery` (`ts-stack@11faa7d16`
//! `packages/sdk/src/wallet/moduleBalanceQuery.ts:1,19-21`): the basket
//! matches `/^(?:balance |p [^ ]+ balance )/`, `balance <basket>` or
//! `p <module> balance <basket>`. Such a query's `totalOutputs` is a balance,
//! not an output count: it is not bounded by `2^32 - 1`, and its answer
//! carries no outputs and no BEEF (`Wallet.interfaces.ts:662-673`).

/// True when `basket` names a BRC-112 balance query.
pub(crate) fn is_balance_query(basket: &str) -> bool {
    if basket.starts_with("balance ") {
        return true;
    }
    // `p [^ ]+ balance `: the module is every character up to the next
    // space, and at least one.
    basket
        .strip_prefix("p ")
        .and_then(|rest| rest.split_once(' '))
        .is_some_and(|(module, rest)| !module.is_empty() && rest.starts_with("balance "))
}

#[cfg(test)]
mod tests {
    use super::is_balance_query;

    #[test]
    fn a_balance_basket_is_told_by_the_reference_pattern_843() {
        for basket in [
            "balance default",
            "balance ",
            "balance a b",
            "p color balance aa",
            "p color balance ",
            "p \u{e9}\n balance x",
        ] {
            assert!(is_balance_query(basket), "{basket:?}");
        }
        for basket in [
            "",
            "default",
            "savings",
            "balance",
            "balances default",
            " balance default",
            "Balance default",
            "p color balance",
            "p  balance aa",
            "p balance aa",
            "p a b balance aa",
            "P color balance aa",
            "p color  balance aa",
            "q color balance aa",
        ] {
            assert!(!is_balance_query(basket), "{basket:?}");
        }
    }
}

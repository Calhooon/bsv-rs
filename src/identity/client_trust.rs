//! The trust step of the reference wallet's `discoverByIdentityKey` over the
//! asked subject's certificates, as far as this crate holds it (#737, the
//! list return): `transformVerifiableCertificatesWithTrust`
//! (`ts-stack@edf6e03`
//! `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:313-382`,
//! called at `Wallet.ts:1010-1013`). Ported: the cap of 256 certificates
//! (`:22`, `:328`), one certificate per type, serial number and certifier
//! (`:360-362`), and the stable sort by the certifier's trust, descending
//! (`:378`; `Array.prototype.sort` is stable, as `sort_by_key` is). The trust is
//! each certificate's `certifier_info.trust`, the one figure this crate holds
//! (no trust settings: #754's record); not ported, the settings' steps: a
//! certificate of a certifier the settings do not name dropped (`:333-334`)
//! and a subject whose summed trust is under the threshold dropped
//! (`:369-374`). The subject groups (`:354-358`) are one after the subject
//! filter (the validated key since #818b), so their order is the members'
//! order. The reference groups by the subject's exact text after a
//! lower-cased filter (`:247-255`,
//! `:354-358`), so an upper-case subject forms its own group with its own
//! threshold and duplicate rule, and a certifier's case is matched against the
//! settings' text; this crate holds keys and treats the cases as one (a stated
//! residue, the #777 rule read; upstream as ts-stack #1483, the keeper's filing
//! at the pin: `identityGroups.get(subject)` keyed by the subject string as it
//! arrives, `:355-359`, the certifier cache by identityKey, `:321-323`; the ask
//! additive, grouping by the key's bytes; the row closes when it lands there).

use crate::identity::types::IdentityCertificate;
use std::cmp::Reverse;
use std::collections::HashSet;

/// The reference's `MAX_IDENTITY_RESULTS` in `identityUtils.ts:22`.
const MAX_IDENTITY_RESULTS: usize = 256;

/// The asked subject's certificates as the trust step orders them: the
/// leading 256, a repeat of a type, serial number and certifier dropped, then
/// the most trusted certifier's ahead, ties in the answer's order.
pub(super) fn ordered_by_trust(certificates: Vec<IdentityCertificate>) -> Vec<IdentityCertificate> {
    let mut seen = HashSet::new();
    let mut kept: Vec<IdentityCertificate> = certificates
        .into_iter()
        .take(MAX_IDENTITY_RESULTS)
        .filter(|c| {
            seen.insert((
                c.type_base64(),
                *c.certificate.serial_number(),
                c.certifier_hex(),
            ))
        })
        .collect();
    kept.sort_by_key(|c| Reverse(c.certifier_info.trust));
    kept
}

#[cfg(test)]
mod tests {
    //! The sort and the repeat rule on certificates this crate cannot
    //! answer with from the door (its parser's trust is one constant): the
    //! reference's order (`identityUtils.ts:360-362,378`).
    use super::*;
    use crate::auth::certificates::Certificate;
    use crate::auth::VerifiableCertificate;
    use crate::identity::types::CertifierInfo;
    use crate::primitives::PrivateKey;
    use indexmap::IndexMap;

    fn cert(serial: u8, certifier: u8, trust: u8) -> IdentityCertificate {
        let key = |n: u8| {
            let mut bytes = [0u8; 32];
            bytes[31] = n;
            PrivateKey::from_bytes(&bytes).unwrap().public_key()
        };
        let certificate = Certificate::new([1; 32], [serial; 32], key(9), key(certifier));
        IdentityCertificate {
            certificate: VerifiableCertificate::new(certificate, IndexMap::new()),
            certifier_info: CertifierInfo {
                trust,
                ..Default::default()
            },
            publicly_revealed_keyring: IndexMap::new(),
            decrypted_fields: IndexMap::new(),
        }
    }

    fn order(certificates: Vec<IdentityCertificate>) -> Vec<(u8, u8)> {
        ordered_by_trust(certificates)
            .iter()
            .map(|c| (c.certificate.serial_number()[0], c.certifier_info.trust))
            .collect()
    }

    #[test]
    fn the_most_trusted_certifier_comes_first_and_ties_keep_the_answers_order_737() {
        let answer = vec![cert(1, 7, 1), cert(2, 8, 3), cert(3, 7, 1), cert(4, 6, 3)];
        assert_eq!(order(answer), [(2, 3), (4, 3), (1, 1), (3, 1)]);
    }

    #[test]
    fn a_repeat_of_type_serial_and_certifier_is_dropped_another_certifier_kept_737() {
        let answer = vec![cert(1, 7, 1), cert(1, 7, 1), cert(1, 8, 1)];
        assert_eq!(order(answer), [(1, 1), (1, 1)]);
        let kept = ordered_by_trust(vec![cert(1, 7, 1), cert(1, 7, 1), cert(1, 8, 1)]);
        assert_ne!(kept[0].certifier_hex(), kept[1].certifier_hex());
    }

    #[test]
    fn the_first_256_certificates_alone_are_judged_737() {
        let answer: Vec<_> = (0..=255u8)
            .map(|s| cert(s, 7, 1))
            .chain([cert(0, 8, 9)])
            .collect();
        let kept = order(answer);
        assert_eq!(kept.len(), 256);
        assert!(kept.iter().all(|&(_, trust)| trust == 1));
    }
}

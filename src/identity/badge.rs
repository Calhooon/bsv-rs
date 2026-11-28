//! Badge construction for a displayable identity.
//!
//! The vouching label a resolved identity carries is shown only where a check
//! of this crate stands behind it: the certificate's certifier is the anchored
//! SocialCert key and Step 7's `verify()` has shown that key signed the
//! attributes. Every other record is handed over with the neutral default
//! badge, so no part of it — the per-type click URL included — names an
//! authority no check stood behind (bsv-rs#1118s).

use super::types::{
    CertifierInfo, DefaultIdentityValues, KnownCertificateType, DEFAULT_SOCIALCERT_CERTIFIER,
};

/// The certifier information to attach to a verified certificate.
///
/// Names the SocialCert certifier only when the verified certificate's
/// certifier IS the anchored key. Step 7's `verify()` has already shown that
/// key signed the attributes, so an author cannot name the anchor without its
/// key. Every other certifier is the neutral default ("Unknown Certifier",
/// trust 0).
pub(crate) fn certifier_info_for(certifier_hex: &str) -> CertifierInfo {
    if certifier_hex == DEFAULT_SOCIALCERT_CERTIFIER {
        CertifierInfo {
            name: "SocialCert".to_string(),
            icon_url: "https://socialcert.net/favicon.ico".to_string(),
            description: "Social identity verification".to_string(),
            trust: 5,
        }
    } else {
        CertifierInfo::default()
    }
}

/// The badge triple (label, icon URL, click URL) a displayable identity shows.
///
/// A certifier-claiming type's badge is a vouching claim, so it is shown only
/// for an anchored certifier; for every other record the neutral default
/// triple is returned, so the per-type click URL cannot point to an authority
/// no check stood behind. Descriptive types (`CoolCert`, `Anyone`, `SelfCert`)
/// and an anchored record keep the triple the per-type match built.
pub(crate) fn displayed_badge_triple(
    known_type: Option<KnownCertificateType>,
    certifier_info: &CertifierInfo,
    label: String,
    icon_url: String,
    click_url: String,
) -> (String, String, String) {
    let certifier_claimed = matches!(
        known_type,
        None | Some(
            KnownCertificateType::XCert
                | KnownCertificateType::DiscordCert
                | KnownCertificateType::EmailCert
                | KnownCertificateType::PhoneCert
                | KnownCertificateType::IdentiCert
                | KnownCertificateType::Registrant
        )
    );
    // The resolve path sets certifier_info from `certifier_info_for`, so its
    // name is either "SocialCert" or "Unknown Certifier" — never empty.
    let anchored = certifier_info.name != "Unknown Certifier";
    if certifier_claimed && !anchored {
        (
            DefaultIdentityValues::BADGE_LABEL.to_string(),
            DefaultIdentityValues::BADGE_ICON_URL.to_string(),
            DefaultIdentityValues::BADGE_CLICK_URL.to_string(),
        )
    } else {
        (label, icon_url, click_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Any 33-byte compressed-point hex that is not the anchor.
    const OTHER_CERTIFIER: &str =
        "02000000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn the_anchored_certifier_is_the_only_vouching_label() {
        let info = certifier_info_for(DEFAULT_SOCIALCERT_CERTIFIER);
        assert_eq!(info.name, "SocialCert");
        assert_eq!(info.trust, 5);
    }

    #[test]
    fn a_non_anchor_certifier_carries_the_neutral_default() {
        let info = certifier_info_for(OTHER_CERTIFIER);
        assert_eq!(info.name, "Unknown Certifier");
        assert_eq!(info.trust, 0);
    }

    // A vouching-looking triple a per-type match builds for an unanchored record
    // (the click URL is the hardcoded authority the neutral override removes).
    fn vouching(label: &str, click: &str) -> (String, String, String) {
        (
            label.to_string(),
            "https://socialcert.net/favicon.ico".to_string(),
            click.to_string(),
        )
    }

    fn is_neutral(t: &(String, String, String)) -> bool {
        t.0 == DefaultIdentityValues::BADGE_LABEL
            && t.1 == DefaultIdentityValues::BADGE_ICON_URL
            && t.2 == DefaultIdentityValues::BADGE_CLICK_URL
    }

    // One named test per certifier-claiming kind: an unanchored record of the
    // kind is neutralised. Dropping the kind from `certifier_claimed` leaves its
    // hardcoded authority click URL in place and turns the test red.
    #[test]
    fn an_unanchored_xcert_badge_is_neutralised() {
        let (l, i, c) = vouching(
            "X account certified by Unknown Certifier",
            "https://socialcert.net",
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::XCert),
            &CertifierInfo::default(),
            l,
            i,
            c,
        );
        assert!(is_neutral(&got));
    }

    #[test]
    fn an_unanchored_discord_badge_is_neutralised() {
        let (l, i, c) = vouching(
            "Discord account certified by Unknown Certifier",
            "https://socialcert.net",
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::DiscordCert),
            &CertifierInfo::default(),
            l,
            i,
            c,
        );
        assert!(is_neutral(&got));
    }

    #[test]
    fn an_unanchored_email_badge_is_neutralised() {
        let (l, i, c) = vouching(
            "Email certified by Unknown Certifier",
            "https://socialcert.net",
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::EmailCert),
            &CertifierInfo::default(),
            l,
            i,
            c,
        );
        assert!(is_neutral(&got));
    }

    #[test]
    fn an_unanchored_phone_badge_is_neutralised() {
        let (l, i, c) = vouching(
            "Phone certified by Unknown Certifier",
            "https://socialcert.net",
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::PhoneCert),
            &CertifierInfo::default(),
            l,
            i,
            c,
        );
        assert!(is_neutral(&got));
    }

    #[test]
    fn an_unanchored_identicert_badge_is_neutralised() {
        let (l, i, c) = vouching(
            "Government ID certified by Unknown Certifier",
            "https://identicert.me",
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::IdentiCert),
            &CertifierInfo::default(),
            l,
            i,
            c,
        );
        assert!(is_neutral(&got));
    }

    #[test]
    fn an_unanchored_registrant_badge_is_neutralised() {
        let (l, i, c) = vouching(
            "Entity certified by Unknown Certifier",
            "https://projectbabbage.com/docs/registrant",
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::Registrant),
            &CertifierInfo::default(),
            l,
            i,
            c,
        );
        assert!(is_neutral(&got));
    }

    #[test]
    fn an_unanchored_generic_badge_is_neutralised() {
        let (l, i, c) = vouching("Certified by Unknown Certifier", "https://socialcert.net");
        let got = displayed_badge_triple(None, &CertifierInfo::default(), l, i, c);
        assert!(is_neutral(&got));
    }

    // A descriptive (non-certifier-claiming) type keeps its badge even when
    // unanchored: over-neutralising would drop an honest descriptive badge.
    #[test]
    fn a_descriptive_type_keeps_its_badge() {
        let triple = (
            "Represents your ability to access this information.".to_string(),
            DefaultIdentityValues::BADGE_ICON_URL.to_string(),
            "https://projectbabbage.com/docs/self-identity".to_string(),
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::SelfCert),
            &CertifierInfo::default(),
            triple.0.clone(),
            triple.1.clone(),
            triple.2.clone(),
        );
        assert_eq!(got, triple);
    }

    // An anchored record keeps the vouching triple the per-type match built.
    #[test]
    fn an_anchored_record_keeps_its_vouching_triple() {
        let anchored = certifier_info_for(DEFAULT_SOCIALCERT_CERTIFIER);
        let triple = (
            "X account certified by SocialCert".to_string(),
            "https://socialcert.net/favicon.ico".to_string(),
            "https://socialcert.net".to_string(),
        );
        let got = displayed_badge_triple(
            Some(KnownCertificateType::XCert),
            &anchored,
            triple.0.clone(),
            triple.1.clone(),
            triple.2.clone(),
        );
        assert_eq!(got, triple);
    }
}

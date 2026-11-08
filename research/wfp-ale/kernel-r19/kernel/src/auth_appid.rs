//! R36: AppId predicate used by the real kernel AUTH_CONNECT classification.
//! The original AppId must match a pinned process image. Current AppId is
//! a distinct field on proxied connections and is NOT a second identity proof.
//! This predicate alone never authorizes: process object, epoch, endpoint,
//! original destination and the one-shot ticket must also match in redirect.rs.

pub fn original_matches_selected(original: &[u8], current: &[u8], selected: &[u8]) -> bool {
    fn valid_utf16_units(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && bytes.len() <= 512
            && bytes.len() % 2 == 0
            && bytes.chunks_exact(2).all(|unit| unit != [0, 0])
    }
    valid_utf16_units(original)
        && valid_utf16_units(current)
        && valid_utf16_units(selected)
        && original == selected
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGINAL: &[u8] = &[b'\\', 0, b'd', 0, b'e', 0, b'v', 0, b'1', 0];
    const PROXY: &[u8] = &[b'\\', 0, b'd', 0, b'e', 0, b'v', 0, b'2', 0];

    #[test]
    fn genuinely_proxied_current_app_can_differ_from_original() {
        assert!(original_matches_selected(ORIGINAL, PROXY, ORIGINAL));
    }
    #[test]
    fn original_and_current_both_selected_remain_supported() {
        assert!(original_matches_selected(ORIGINAL, ORIGINAL, ORIGINAL));
    }
    #[test]
    fn broker_original_cannot_claim_selected() {
        assert!(!original_matches_selected(PROXY, ORIGINAL, ORIGINAL));
    }
    #[test]
    fn malformed_or_missing_current_is_not_proof() {
        for candidate in [&[][..], &[0, 0][..], &[b'A'][..], &[b'A', 0, 0, 0][..]] {
            assert!(!original_matches_selected(ORIGINAL, candidate, ORIGINAL));
        }
    }
    #[test]
    fn malformed_original_is_denied() {
        assert!(!original_matches_selected(&[b'A', 0, 0, 0], PROXY, ORIGINAL));
        assert!(!original_matches_selected(&[], PROXY, ORIGINAL));
    }
    #[test]
    fn invalid_pinned_selected_is_never_allowed() {
        assert!(!original_matches_selected(&[0, 0], PROXY, &[0, 0]));
    }
    #[test]
    fn arbitrary_app_without_pinned_original_denied() {
        assert!(!original_matches_selected(PROXY, PROXY, ORIGINAL));
    }
}

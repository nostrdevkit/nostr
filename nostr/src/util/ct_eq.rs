use core::hint::black_box;

#[inline]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;

    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }

    black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_slices_equal_different_lengths() {
        let a: [u8; 3] = [0, 0, 0];
        let b: [u8; 4] = [0, 0, 0, 0];

        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn ct_eq_slices_equal() {
        let a: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let b: [u8; 8] = [1, 2, 3, 4, 4, 3, 2, 1];

        let a_eq_a = constant_time_eq(&a, &a);
        let a_eq_b = constant_time_eq(&a, &b);

        assert!(a_eq_a);
        assert!(!a_eq_b);

        let c: [u8; 16] = [0u8; 16];

        let a_eq_c = constant_time_eq(&a, &c);
        assert!(!a_eq_c);
    }

    #[test]
    fn ct_eq_detects_any_bit_flip() {
        let a: [u8; 32] = [7; 32];

        // Every possible byte value in every position must be detected
        for i in 0..a.len() {
            for delta in 1..=255u8 {
                let mut b: [u8; 32] = a;
                b[i] ^= delta;
                assert!(!constant_time_eq(black_box(&a), black_box(&b)));
            }
        }

        assert!(constant_time_eq(black_box(&a), black_box(&a)));
    }

    #[test]
    fn ct_eq_empty_slices() {
        assert!(constant_time_eq(black_box(&[]), black_box(&[])));
        assert!(!constant_time_eq(black_box(&[]), black_box(&[0u8])));
        assert!(!constant_time_eq(black_box(&[0u8]), black_box(&[])));
    }
}

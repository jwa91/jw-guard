use alloc::string::String;

use crate::CanonicalPath;

/// Stable ordering semantics for canonical forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanonicalOrdering {
    Lexicographic,
    StableInput,
}

impl CanonicalOrdering {
    pub fn order_strings(self, values: &mut [String]) {
        if matches!(self, Self::Lexicographic) {
            values.sort();
        }
    }

    pub fn order_paths(self, values: &mut [CanonicalPath]) {
        if matches!(self, Self::Lexicographic) {
            values.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        }
    }
}

pub fn stable_sort_by_key<T, K, F>(values: &mut [T], mut key: F)
where
    K: Ord,
    F: FnMut(&T) -> K,
{
    values.sort_by_key(|value| key(value));
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use crate::{CanonicalOrdering, CanonicalPath, stable_sort_by_key};

    #[test]
    fn lexicographic_order_sorts_strings_deterministically() {
        let mut values = vec![
            String::from("zeta"),
            String::from("alpha"),
            String::from("alpha-1"),
        ];

        CanonicalOrdering::Lexicographic.order_strings(&mut values);
        assert_eq!(values, vec!["alpha", "alpha-1", "zeta"]);
    }

    #[test]
    fn stable_input_order_keeps_strings_unchanged() {
        let mut values = vec![String::from("beta"), String::from("alpha")];
        CanonicalOrdering::StableInput.order_strings(&mut values);
        assert_eq!(values, vec!["beta", "alpha"]);
    }

    #[test]
    fn lexicographic_order_sorts_paths_by_canonical_string() {
        let mut paths = vec![
            CanonicalPath::try_new("zeta/root").expect("valid path"),
            CanonicalPath::try_new("alpha/leaf").expect("valid path"),
            CanonicalPath::try_new("alpha/core").expect("valid path"),
        ];

        CanonicalOrdering::Lexicographic.order_paths(&mut paths);
        let ordered: Vec<&str> = paths.iter().map(CanonicalPath::as_str).collect();
        assert_eq!(ordered, vec!["alpha/core", "alpha/leaf", "zeta/root"]);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Item {
        key: u8,
        id: u8,
    }

    #[test]
    fn stable_sort_by_key_preserves_input_order_for_equal_keys() {
        let mut items = vec![
            Item { key: 2, id: 1 },
            Item { key: 1, id: 2 },
            Item { key: 2, id: 3 },
            Item { key: 1, id: 4 },
        ];

        stable_sort_by_key(&mut items, |item| item.key);
        let ids: Vec<u8> = items.iter().map(|item| item.id).collect();
        assert_eq!(ids, vec![2, 4, 1, 3]);
    }
}

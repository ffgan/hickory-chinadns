use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::config::Error;

/// Suffix map. The first tag stored for a suffix wins.
/// Callers load higher-priority lists first.
#[derive(Debug, Default)]
pub struct DomainMap {
    nodes: Vec<Node>,
    entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainTag {
    Chn,
    Gfw,
    Null,
    /// Matched no list. Resolved by the china/trust IP test.
    None,
    Group(usize),
}

#[derive(Debug, Default)]
struct Node {
    children: HashMap<Box<str>, usize>,
    tag: Option<DomainTag>,
}

impl DomainMap {
    pub fn new() -> Self {
        Self {
            nodes: vec![Node::default()],
            entries: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries
    }

    pub fn load_file(&mut self, path: &Path, tag: DomainTag) -> Result<(), Error> {
        let text = fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
        for raw in text.lines() {
            let line = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if line.is_empty() || line.starts_with('.') || line.contains(char::is_whitespace) {
                continue;
            }
            self.insert(&line, tag);
        }
        Ok(())
    }

    fn insert(&mut self, domain: &str, tag: DomainTag) {
        let mut labels: Vec<&str> = domain
            .split('.')
            .filter(|label| !label.is_empty())
            .collect();
        if labels.len() > 8 {
            labels = labels.split_off(labels.len() - 8);
        }
        let mut node = 0;
        for label in labels.into_iter().rev() {
            node = self.child(node, label);
        }
        if self.nodes[node].tag.is_none() {
            self.nodes[node].tag = Some(tag);
            self.entries += 1;
        }
    }

    fn child(&mut self, node: usize, label: &str) -> usize {
        if let Some(&next) = self.nodes[node].children.get(label) {
            return next;
        }
        let next = self.nodes.len();
        self.nodes.push(Node::default());
        self.nodes[node]
            .children
            .insert(Box::<str>::from(label), next);
        next
    }

    /// Longest suffix wins. `www.google.com` matches `google.com` before `com`.
    pub fn lookup(&self, qname: &str) -> Option<DomainTag> {
        let name = qname.trim().trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').filter(|label| !label.is_empty()).collect();
        let mut node = 0;
        let mut found = None;
        for label in labels.into_iter().rev() {
            match self.nodes[node].children.get(label) {
                Some(&next) => {
                    node = next;
                    if self.nodes[node].tag.is_some() {
                        found = self.nodes[node].tag;
                    }
                }
                None => break,
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_suffix_and_first_insert_wins() {
        let mut map = DomainMap::new();
        map.insert("example.com", DomainTag::Group(1));
        map.insert("example.com", DomainTag::Group(0));
        map.insert("google.com", DomainTag::Gfw);
        map.insert("com", DomainTag::Chn);
        assert_eq!(map.lookup("www.example.com"), Some(DomainTag::Group(1)));
        assert_eq!(map.lookup("Google.COM."), Some(DomainTag::Gfw));
        assert_eq!(map.lookup("other.com"), Some(DomainTag::Chn));
        assert_eq!(map.lookup("org"), None);
        assert_eq!(map.len(), 3);
    }
}

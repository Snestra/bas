//! Matches identifier metadata to queries and projects it to safe summaries.

use std::collections::BTreeMap;

use crate::output::SecretSummary;
use crate::reference::{ProfileName, SecretRef};
use crate::secrets::Identifier;

/// Result of matching queries against secret keys.
#[derive(Debug, Default)]
pub struct Discovery {
    pub matches: Vec<SecretSummary>,
    /// Queries that matched no key.
    pub unmatched: Vec<String>,
}

/// Matches each query as a case-insensitive substring of secret keys.
///
/// With no queries every identifier is returned. Secrets sharing a key are all returned and
/// flagged, never silently reduced to one. Results are sorted by key, then ID.
pub fn discover(
    profile: &ProfileName,
    identifiers: Vec<Identifier>,
    queries: &[String],
) -> Discovery {
    let mut key_counts: BTreeMap<String, usize> = BTreeMap::new();
    for identifier in &identifiers {
        *key_counts.entry(identifier.key.clone()).or_default() += 1;
    }
    let lowered: Vec<String> = queries.iter().map(|query| query.to_lowercase()).collect();
    let mut hit = vec![false; queries.len()];
    let mut matches = Vec::new();
    for identifier in identifiers {
        let key = identifier.key.to_lowercase();
        let matched: Vec<String> = queries
            .iter()
            .zip(&lowered)
            .zip(hit.iter_mut())
            .filter(|((_, query), _)| key.contains(query.as_str()))
            .map(|((query, _), hit)| {
                *hit = true;
                query.clone()
            })
            .collect();
        if queries.is_empty() || !matched.is_empty() {
            let duplicate_key = key_counts
                .get(&identifier.key)
                .is_some_and(|count| *count > 1);
            matches.push(SecretSummary {
                reference: SecretRef {
                    profile: profile.clone(),
                    id: identifier.id,
                },
                key: identifier.key,
                project_ids: identifier.project_ids,
                matched,
                duplicate_key,
            });
        }
    }
    matches.sort_by(|a, b| a.key.cmp(&b.key).then(a.reference.cmp(&b.reference)));
    let unmatched = queries
        .iter()
        .zip(hit)
        .filter(|(_, hit)| !hit)
        .map(|(query, _)| query.clone())
        .collect();
    Discovery { matches, unmatched }
}

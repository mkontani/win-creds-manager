//! In-memory DEK cache with idle / absolute / use-count expiry.
//!
//! Pure logic: every method takes `now`, so the policy is tested without
//! sleeping. Entries hold the key in a `Zeroizing` buffer and are wiped when
//! removed.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use wcm_core::slot::Dek;

use crate::protocol::{EntryInfo, PolicyInfo, VaultId};

/// When a cached key is forgotten. The first condition reached wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Forget a key this long after its last use.
    pub idle: Duration,
    /// Forget a key this long after it was cached, even if in use.
    pub ttl: Duration,
    /// Forget a key after it was handed out this many times.
    pub max_uses: Option<u32>,
}

impl Policy {
    /// idle 10 min, ttl 1 h, unlimited uses.
    pub const DEFAULT: Policy = Policy {
        idle: Duration::from_secs(10 * 60),
        ttl: Duration::from_secs(60 * 60),
        max_uses: None,
    };

    /// Reportable form.
    pub fn info(&self) -> PolicyInfo {
        PolicyInfo {
            idle_secs: self.idle.as_secs(),
            ttl_secs: self.ttl.as_secs(),
            max_uses: self.max_uses,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy::DEFAULT
    }
}

struct Entry {
    dek: Dek,
    path: String,
    cached_at: Instant,
    last_used: Instant,
    uses: u32,
}

/// The cache: one entry per vault id.
pub struct Cache {
    policy: Policy,
    entries: HashMap<VaultId, Entry>,
}

impl Cache {
    /// Empty cache under `policy`.
    pub fn new(policy: Policy) -> Cache {
        Cache {
            policy,
            entries: HashMap::new(),
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Number of cached vaults (expired entries count until swept).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Caches (or replaces) the key for `vault_id`; counters start over.
    pub fn put(&mut self, vault_id: VaultId, path: String, dek: Dek, now: Instant) {
        self.entries.insert(
            vault_id,
            Entry {
                dek,
                path,
                cached_at: now,
                last_used: now,
                uses: 0,
            },
        );
    }

    /// The key for `vault_id` unless expired (an expired entry is removed).
    /// Counts as a use; the entry is removed once `max_uses` is reached.
    pub fn get(&mut self, vault_id: &VaultId, now: Instant) -> Option<Dek> {
        let expired = expired_under(&self.policy, self.entries.get(vault_id)?, now);
        if expired {
            self.entries.remove(vault_id);
            return None;
        }
        let entry = self.entries.get_mut(vault_id)?;
        entry.uses += 1;
        entry.last_used = now;
        let dek = entry.dek.clone();
        let exhausted = self.policy.max_uses.is_some_and(|max| entry.uses >= max);
        if exhausted {
            self.entries.remove(vault_id);
        }
        Some(dek)
    }

    /// Forgets one vault; `true` if it was cached.
    pub fn lock(&mut self, vault_id: &VaultId) -> bool {
        self.entries.remove(vault_id).is_some()
    }

    /// Forgets everything; returns how many entries were dropped.
    pub fn lock_all(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
        n
    }

    /// Drops expired entries; returns how many.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        let policy = self.policy;
        self.entries.retain(|_, e| !expired_under(&policy, e, now));
        before - self.entries.len()
    }

    /// Entries sorted by vault id (no secrets).
    pub fn status(&self, now: Instant) -> Vec<EntryInfo> {
        let mut rows: Vec<EntryInfo> = self
            .entries
            .iter()
            .map(|(id, e)| EntryInfo {
                vault_id_hex: hex(id),
                path: e.path.clone(),
                age_secs: now.saturating_duration_since(e.cached_at).as_secs(),
                idle_secs: now.saturating_duration_since(e.last_used).as_secs(),
                uses: e.uses,
                expires_in_secs: expires_in(&self.policy, e, now).as_secs(),
            })
            .collect();
        rows.sort_by(|a, b| a.vault_id_hex.cmp(&b.vault_id_hex));
        rows
    }
}

fn expired_under(policy: &Policy, e: &Entry, now: Instant) -> bool {
    now.saturating_duration_since(e.last_used) >= policy.idle
        || now.saturating_duration_since(e.cached_at) >= policy.ttl
}

fn expires_in(policy: &Policy, e: &Entry, now: Instant) -> Duration {
    let idle_left = policy
        .idle
        .saturating_sub(now.saturating_duration_since(e.last_used));
    let ttl_left = policy
        .ttl
        .saturating_sub(now.saturating_duration_since(e.cached_at));
    idle_left.min(ttl_left)
}

/// Lowercase hex (matches `Header::vault_id_hex`).
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;

    const ID: VaultId = [1; 16];
    const OTHER: VaultId = [2; 16];

    fn policy(idle: u64, ttl: u64, max_uses: Option<u32>) -> Policy {
        Policy {
            idle: Duration::from_secs(idle),
            ttl: Duration::from_secs(ttl),
            max_uses,
        }
    }

    fn dek(b: u8) -> Dek {
        Zeroizing::new([b; 32])
    }

    fn at(t0: Instant, secs: u64) -> Instant {
        t0 + Duration::from_secs(secs)
    }

    #[test]
    fn default_policy_matches_the_spec() {
        assert_eq!(Policy::DEFAULT.idle, Duration::from_secs(600));
        assert_eq!(Policy::DEFAULT.ttl, Duration::from_secs(3600));
        assert_eq!(Policy::DEFAULT.max_uses, None);
        assert_eq!(Policy::default(), Policy::DEFAULT);
        assert_eq!(
            Policy::DEFAULT.info(),
            PolicyInfo {
                idle_secs: 600,
                ttl_secs: 3600,
                max_uses: None
            }
        );
    }

    #[test]
    fn hit_until_idle_timeout_measured_from_last_use() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(10, 100, None));
        c.put(ID, "p".into(), dek(1), t0);
        assert_eq!(*c.get(&ID, at(t0, 9)).expect("hit"), [1u8; 32]);
        assert!(c.get(&ID, at(t0, 18)).is_some(), "9s after last use");
        assert!(c.get(&ID, at(t0, 28)).is_none(), "10s after last use");
        assert!(c.is_empty(), "expired entry is dropped");
    }

    #[test]
    fn ttl_expires_even_while_in_use() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(10, 25, None));
        c.put(ID, "p".into(), dek(1), t0);
        assert!(c.get(&ID, at(t0, 9)).is_some());
        assert!(c.get(&ID, at(t0, 18)).is_some());
        assert!(c.get(&ID, at(t0, 25)).is_none(), "ttl reached");
        assert!(c.is_empty());
    }

    #[test]
    fn max_uses_evicts_after_the_last_allowed_use() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(100, 100, Some(2)));
        c.put(ID, "p".into(), dek(1), t0);
        assert!(c.get(&ID, t0).is_some());
        assert_eq!(c.len(), 1);
        assert!(c.get(&ID, t0).is_some(), "second use is served");
        assert!(c.is_empty(), "…and evicts");
        assert!(c.get(&ID, t0).is_none());
    }

    #[test]
    fn put_replaces_the_key_and_resets_counters() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(100, 100, Some(2)));
        c.put(ID, "p".into(), dek(1), t0);
        assert!(c.get(&ID, t0).is_some());
        c.put(ID, "q".into(), dek(2), at(t0, 5));
        let rows = c.status(at(t0, 5));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].uses, 0);
        assert_eq!(rows[0].path, "q");
        assert_eq!(rows[0].age_secs, 0);
        assert_eq!(*c.get(&ID, at(t0, 5)).expect("new key"), [2u8; 32]);
    }

    #[test]
    fn lock_one_and_lock_all() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(100, 100, None));
        c.put(ID, "a".into(), dek(1), t0);
        c.put(OTHER, "b".into(), dek(2), t0);
        assert!(c.lock(&ID));
        assert!(!c.lock(&ID), "already gone");
        assert_eq!(c.len(), 1);
        assert_eq!(c.lock_all(), 1);
        assert!(c.is_empty());
        assert_eq!(c.lock_all(), 0);
    }

    #[test]
    fn sweep_drops_only_expired_entries() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(10, 100, None));
        c.put(ID, "a".into(), dek(1), t0);
        c.put(OTHER, "b".into(), dek(2), at(t0, 5));
        assert_eq!(c.sweep(at(t0, 12)), 1, "only the first is idle-expired");
        assert_eq!(c.len(), 1);
        assert!(c.get(&OTHER, at(t0, 12)).is_some());
        assert_eq!(c.sweep(at(t0, 12)), 0);
    }

    #[test]
    fn status_reports_age_idle_uses_and_remaining_time() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(10, 25, None));
        c.put(ID, "/v/vault.wcm".into(), dek(1), t0);
        assert!(c.get(&ID, at(t0, 3)).is_some());
        let rows = c.status(at(t0, 5));
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.vault_id_hex, "01".repeat(16));
        assert_eq!(r.path, "/v/vault.wcm");
        assert_eq!(r.age_secs, 5);
        assert_eq!(r.idle_secs, 2);
        assert_eq!(r.uses, 1);
        assert_eq!(r.expires_in_secs, 8, "min(idle 10-2, ttl 25-5)");
        // Keep the idle window refreshed (each gap below the 10s idle limit)
        // so that ttl, not idle, ends up the binding constraint below.
        assert!(c.get(&ID, at(t0, 12)).is_some());
        assert!(c.get(&ID, at(t0, 20)).is_some());
        assert_eq!(
            c.status(at(t0, 21))[0].expires_in_secs,
            4,
            "min(10-1, 25-21)"
        );
    }

    #[test]
    fn status_is_sorted_by_vault_id() {
        let t0 = Instant::now();
        let mut c = Cache::new(policy(10, 25, None));
        c.put(OTHER, "b".into(), dek(2), t0);
        c.put(ID, "a".into(), dek(1), t0);
        let ids: Vec<String> = c.status(t0).into_iter().map(|r| r.vault_id_hex).collect();
        assert_eq!(ids, vec!["01".repeat(16), "02".repeat(16)]);
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0xab, 0x01, 0xff]), "ab01ff");
    }
}

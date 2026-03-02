use crate::zeroizing::SecretBytes;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct CacheEntry {
    key: SecretBytes,
    last_accessed: Instant,
}

/// A TTL-based cache for derived keys. All entries are zeroized on eviction or drop.
pub struct KeyCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl KeyCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        KeyCache {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    pub fn get(&self, id: &str) -> Option<SecretBytes> {
        let mut map = self.entries.lock().unwrap();
        let entry = map.get(id)?;
        if entry.last_accessed.elapsed() > self.ttl {
            map.remove(id);
            return None;
        }
        let cloned = entry.key.clone();
        // Update access time
        map.get_mut(id).unwrap().last_accessed = Instant::now();
        Some(cloned)
    }

    pub fn insert(&self, id: &str, key: SecretBytes) {
        let mut map = self.entries.lock().unwrap();
        self.evict_expired_inner(&mut map);

        if map.len() >= self.max_entries && !map.contains_key(id) {
            // Evict least recently used
            if let Some(lru_key) = map
                .iter()
                .min_by_key(|(_, e)| e.last_accessed)
                .map(|(k, _)| k.clone())
            {
                map.remove(&lru_key);
            }
        }

        map.insert(
            id.to_string(),
            CacheEntry {
                key,
                last_accessed: Instant::now(),
            },
        );
    }

    pub fn clear(&self) {
        let mut map = self.entries.lock().unwrap();
        map.clear();
    }

    pub fn evict_expired(&self) {
        let mut map = self.entries.lock().unwrap();
        self.evict_expired_inner(&mut map);
    }

    fn evict_expired_inner(&self, map: &mut HashMap<String, CacheEntry>) {
        map.retain(|_, entry| entry.last_accessed.elapsed() <= self.ttl);
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Drop for KeyCache {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_insert_and_get() {
        let cache = KeyCache::new(Duration::from_secs(5), 10);
        cache.insert("key1", SecretBytes::from_slice(&[1, 2, 3]));
        let val = cache.get("key1").unwrap();
        assert_eq!(val.expose(), &[1, 2, 3]);
    }

    #[test]
    fn test_missing_key() {
        let cache = KeyCache::new(Duration::from_secs(5), 10);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_expiry() {
        let cache = KeyCache::new(Duration::from_millis(50), 10);
        cache.insert("key1", SecretBytes::from_slice(&[1, 2, 3]));
        assert!(cache.get("key1").is_some());

        thread::sleep(Duration::from_millis(100));
        assert!(cache.get("key1").is_none());
    }

    #[test]
    fn test_max_entries_evicts_lru() {
        let cache = KeyCache::new(Duration::from_secs(5), 2);
        cache.insert("a", SecretBytes::from_slice(&[1]));
        thread::sleep(Duration::from_millis(10));
        cache.insert("b", SecretBytes::from_slice(&[2]));
        thread::sleep(Duration::from_millis(10));

        // Access "a" to make it more recent
        cache.get("a");
        thread::sleep(Duration::from_millis(10));

        // Insert "c" — should evict "b" (least recently accessed)
        cache.insert("c", SecretBytes::from_slice(&[3]));
        assert_eq!(cache.len(), 2);
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn test_clear() {
        let cache = KeyCache::new(Duration::from_secs(5), 10);
        cache.insert("a", SecretBytes::from_slice(&[1]));
        cache.insert("b", SecretBytes::from_slice(&[2]));
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_evict_expired() {
        let cache = KeyCache::new(Duration::from_millis(50), 10);
        cache.insert("a", SecretBytes::from_slice(&[1]));
        thread::sleep(Duration::from_millis(100));
        cache.insert("b", SecretBytes::from_slice(&[2]));

        cache.evict_expired();
        assert_eq!(cache.len(), 1);
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_some());
    }
}

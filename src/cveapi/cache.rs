// CVE cache implementation

use std::collections::HashMap;
use crate::models::Vulnerability;

// Cache to store previously retrieved CVE data
static mut CVE_CACHE: Option<HashMap<String, Vulnerability>> = None;

/// Initialize the CVE cache
#[allow(static_mut_refs)]
pub fn init_cve_cache() {
    unsafe {
        if CVE_CACHE.is_none() {
            CVE_CACHE = Some(HashMap::new());
        }
    }
}

/// Get a vulnerability from the cache
#[allow(static_mut_refs)]
pub fn get_from_cache(cve_id: &str) -> Option<Vulnerability> {
    unsafe {
        if let Some(cache) = &CVE_CACHE {
            return cache.get(cve_id).cloned();
        }
    }
    None
}

/// Add a vulnerability to the cache
#[allow(static_mut_refs)]
pub fn add_to_cache(cve_id: String, vulnerability: Vulnerability) {
    unsafe {
        if let Some(cache) = &mut CVE_CACHE {
            cache.insert(cve_id, vulnerability);
        }
    }
}

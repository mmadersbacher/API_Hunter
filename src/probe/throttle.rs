use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use std::time::Duration;
use tokio::time::sleep;

/// A permit that holds both global and per-host semaphore permits.
pub struct ThrottlePermit {
    _global: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
}

pub struct Throttle {
    global: Arc<Semaphore>,
    per_host: DashMap<String, Arc<Semaphore>>,
    default_per_host: usize,
}

impl Throttle {
    pub fn new(global_limit: usize, default_per_host: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_limit)),
            per_host: DashMap::new(),
            default_per_host,
        }
    }

    #[allow(dead_code)]
    pub fn set_host_limit(&self, host: &str, limit: usize) {
        self.per_host.insert(host.to_string(), Arc::new(Semaphore::new(limit)));
    }

    /// Reduce host limit for a duration (cooldown_secs). After cooldown, restore to default_per_host.
    pub fn cool_down_host(&self, host: &str, new_limit: usize, cooldown_secs: u64) {
        let host_name = host.to_string();
        let per_host_map = self.per_host.clone();
        let default = self.default_per_host;
        // Replace immediately
        per_host_map.insert(host_name.clone(), Arc::new(Semaphore::new(new_limit)));

        // Spawn a task to restore after cooldown
        tokio::spawn(async move {
            sleep(Duration::from_secs(cooldown_secs)).await;
            per_host_map.insert(host_name.clone(), Arc::new(Semaphore::new(default)));
        });
    }

    async fn get_host_semaphore(&self, host: &str) -> Arc<Semaphore> {
        if let Some(s) = self.per_host.get(host) {
            return s.value().clone();
        }
        let sem = Arc::new(Semaphore::new(self.default_per_host));
        self.per_host.insert(host.to_string(), sem.clone());
        sem
    }

    pub async fn acquire(&self, host: &str) -> ThrottlePermit {
        let g = self.global.clone();
        let host_sem = self.get_host_semaphore(host).await;
        // Acquire global then host
        let gperm = g.clone().acquire_owned().await.expect("global semaphore closed");
        let hperm = host_sem.clone().acquire_owned().await.expect("host semaphore closed");
        ThrottlePermit { _global: gperm, _host: hperm }
    }
}

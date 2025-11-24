use tokio::sync::Semaphore;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock;

/// High-performance concurrent probe executor
pub struct ConcurrentProbe {
    semaphore: Arc<Semaphore>,
    completed: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
}

impl ConcurrentProbe {
    pub fn new(concurrency: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(concurrency)),
            completed: Arc::new(AtomicUsize::new(0)),
            errors: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    /// Execute multiple tasks concurrently with semaphore-based rate limiting
    pub async fn execute<T, F, Fut>(
        &self,
        tasks: Vec<T>,
        task_fn: F,
    ) -> Vec<Option<Fut::Output>>
    where
        F: Fn(T) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future + Send + 'static,
        Fut::Output: Send + 'static,
        T: Send + 'static,
    {
        let mut futures = FuturesUnordered::new();
        
        for task in tasks {
            let permit = self.semaphore.clone().acquire_owned().await.unwrap();
            let task_fn = task_fn.clone();
            let completed = self.completed.clone();
            
            futures.push(tokio::spawn(async move {
                let result = task_fn(task).await;
                completed.fetch_add(1, Ordering::Relaxed);
                drop(permit); // Release semaphore
                Some(result)
            }));
        }
        
        let mut results = Vec::new();
        while let Some(result) = futures.next().await {
            match result {
                Ok(Some(output)) => results.push(Some(output)),
                Ok(None) => results.push(None),
                Err(_) => {
                    self.errors.fetch_add(1, Ordering::Relaxed);
                    results.push(None);
                }
            }
        }
        
        results
    }
    
    pub fn get_stats(&self) -> (usize, usize) {
        (
            self.completed.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }
}

/// Shared result cache using parking_lot RwLock for better performance
pub struct ResultCache<K, V> {
    cache: Arc<RwLock<ahash::AHashMap<K, V>>>,
}

impl<K: std::hash::Hash + Eq + Clone, V: Clone> ResultCache<K, V> {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(ahash::AHashMap::new())),
        }
    }
    
    pub fn get(&self, key: &K) -> Option<V> {
        self.cache.read().get(key).cloned()
    }
    
    pub fn insert(&self, key: K, value: V) {
        self.cache.write().insert(key, value);
    }
    
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }
}

impl<K, V> Default for ResultCache<K, V> 
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

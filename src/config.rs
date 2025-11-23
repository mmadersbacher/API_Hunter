use serde::Deserialize;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub concurrency: u16,
    pub per_host: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self { concurrency: 50, per_host: 6 }
    }
}

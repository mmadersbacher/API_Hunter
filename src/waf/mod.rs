// WAF Detection and Bypass Module
// Only activates with explicit flags - no automatic exploitation

pub mod detector;
pub mod bypass;
pub mod signatures;

pub use detector::{WafDetector, WafType, WafDetection};
pub use bypass::{WafBypass, BypassTechnique, BypassResult};
pub use signatures::WafSignature;

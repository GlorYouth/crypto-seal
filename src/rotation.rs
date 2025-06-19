pub mod manager;

use serde::{Deserialize, Serialize};

/// 密钥轮换策略，定义了密钥的生命周期和使用限制。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationPolicy {
    /// 密钥的有效天数。
    pub validity_period_days: u32,
    /// 密钥在被轮换前的最大允许使用次数。
    pub max_usage_count: Option<u64>,
    /// 在密钥过期前多少天，系统就应该开始准备或触发下一次轮换。
    pub rotation_start_days: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            validity_period_days: 90,
            max_usage_count: Some(10_000_000),
            rotation_start_days: 7,
        }
    }
}

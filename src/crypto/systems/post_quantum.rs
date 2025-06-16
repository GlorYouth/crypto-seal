//! 后量子加密算法模块
//!
//! 本模块包含Kyber等后量子加密算法的实现，提供符合CryptographicSystem特征的接口

pub mod kyber;

// 重新导出Kyber系统，方便用户使用
pub use kyber::KyberCryptoSystem; 
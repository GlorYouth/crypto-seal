//! 传统加密算法模块
//!
//! 本模块包含RSA等传统加密算法的实现，提供符合CryptographicSystem特征的接口

pub mod rsa;

// 重新导出RSA系统，方便用户使用
pub use rsa::RsaCryptoSystem; 
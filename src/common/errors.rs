use std::error::Error as StdError;
use std::fmt;

/// 加密操作可能遇到的错误类型
#[derive(Debug)]
pub enum Error {
    /// RSA/传统加密相关错误
    Traditional(String),

    /// Kyber/后量子加密相关错误
    PostQuantum(String),

    /// 密钥存储和管理相关错误
    KeyStorage(String),

    /// 序列化/反序列化错误
    Serialization(String),

    /// 输入/输出错误
    Io(std::io::Error),

    /// 数据格式错误
    Format(String),

    /// 密钥错误 (例如无效的密码或损坏的密钥)
    Key(String),

    /// 算法操作失败
    Operation(String),
    /// 加密失败
    EncryptionFailed(String),
    /// 解密失败
    DecryptionFailed(String),
    /// 签名验证失败
    Verification(String),
    /// 签名操作错误
    Signature(String),
    /// 密钥导入失败
    KeyImportFailed(String),
    /// 密钥导出失败
    KeyExportFailed(String),
    /// 密钥管理错误
    KeyManagement(String),
    /// 配置错误
    Configuration(String),
    /// AAD 不匹配错误
    AadMismatch,
    /// Bincode 序列化/反序列化错误
    Bincode(String),
    /// PKCS#8 格式错误
    Pkcs8(rsa::pkcs8::Error),
    /// SPKI 格式错误
    Spki(rsa::pkcs8::spki::Error),
    /// 异步任务错误
    AsyncTask(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Traditional(msg) => write!(f, "传统加密错误: {}", msg),
            Error::PostQuantum(msg) => write!(f, "后量子加密错误: {}", msg),
            Error::KeyStorage(msg) => write!(f, "密钥存储错误: {}", msg),
            Error::Serialization(msg) => write!(f, "序列化错误: {}", msg),
            Error::Io(e) => write!(f, "I/O 错误: {}", e),
            Error::Format(msg) => write!(f, "格式错误: {}", msg),
            Error::Key(msg) => write!(f, "密钥错误: {}", msg),
            Error::Operation(msg) => write!(f, "操作失败: {}", msg),
            Error::EncryptionFailed(msg) => write!(f, "加密失败: {}", msg),
            Error::DecryptionFailed(msg) => write!(f, "解密失败: {}", msg),
            Error::Verification(msg) => write!(f, "签名验证失败: {}", msg),
            Error::Signature(msg) => write!(f, "签名操作错误: {}", msg),
            Error::KeyImportFailed(msg) => write!(f, "密钥导入失败: {}", msg),
            Error::KeyExportFailed(msg) => write!(f, "密钥导出失败: {}", msg),
            Error::KeyManagement(msg) => write!(f, "密钥管理错误: {}", msg),
            Error::Configuration(msg) => write!(f, "配置错误: {}", msg),
            Error::AadMismatch => write!(f, "AAD 不匹配"),
            Error::Bincode(msg) => write!(f, "Bincode 错误: {}", msg),
            Error::Pkcs8(e) => write!(f, "PKCS#8 错误: {}", e),
            Error::Spki(e) => write!(f, "SPKI 错误: {}", e),
            Error::AsyncTask(msg) => write!(f, "异步任务错误: {}", msg),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Pkcs8(e) => Some(e),
            Error::Spki(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Format(format!("Base64解码错误: {}", err))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serialization(format!("JSON错误: {}", err))
    }
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Self {
        Error::Configuration(err.to_string())
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(err: bincode::error::EncodeError) -> Self {
        Error::Bincode(err.to_string())
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(err: bincode::error::DecodeError) -> Self {
        Error::Bincode(err.to_string())
    }
}

impl From<rsa::pkcs8::Error> for Error {
    fn from(err: rsa::pkcs8::Error) -> Self {
        Error::Pkcs8(err)
    }
}

impl From<rsa::pkcs8::spki::Error> for Error {
    fn from(err: rsa::pkcs8::spki::Error) -> Self {
        Error::Spki(err)
    }
}

#[cfg(feature = "parallel")]
impl From<tokio::task::JoinError> for Error {
    fn from(err: tokio::task::JoinError) -> Self {
        Error::AsyncTask(err.to_string())
    }
}

// 可以添加更多转换实现，方便错误处理
impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Format(format!("UTF-8转换错误: {}", err))
    }
}

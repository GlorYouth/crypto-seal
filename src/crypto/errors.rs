use std::fmt;
use std::error::Error as StdError;

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
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Io(e) => Some(e),
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

// 可以添加更多转换实现，方便错误处理
impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Format(format!("UTF-8转换错误: {}", err))
    }
} 
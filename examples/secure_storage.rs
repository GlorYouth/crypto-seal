//! Secure storage 示例

#[cfg(feature = "secure-storage")]
use secrecy::SecretString;
#[cfg(feature = "secure-storage")]
use seal_kit::EncryptedKeyContainer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 如果启用了 secure-storage 特性，则运行示例；否则提示如何运行
    #[cfg(feature = "secure-storage")] {
        // 密码字符串
        let password = SecretString::new(Box::from("mypassword"));
        // 原始密钥数据
        let data = b"super_secret_key";

        // 创建加密容器
        let container = EncryptedKeyContainer::new(&password, data, "my-algo")?;
        // 从容器中恢复密钥
        let recovered = container.get_key(&password)?;
        println!("Recovered key: {:?}", String::from_utf8(recovered.to_vec())?);
        assert_eq!(data, recovered.as_slice());
    }
    #[cfg(not(feature = "secure-storage"))] {
        println!("示例需要启用 secure-storage 特性:");
        println!("cargo run --example secure_storage --features secure-storage");
    }
    Ok(())
} 
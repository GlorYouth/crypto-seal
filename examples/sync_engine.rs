#![cfg(feature = "post-quantum")]
use std::{fs, sync::Arc};
use crypto_seal::{QSealEngine, ConfigManager, Error, PostQuantumKyber};

fn main() -> Result<(), Error> {
    let data = "示例数据: 同步引擎".as_bytes();

    println!("\n[方法一：默认配置开始]");
    // 方法一：默认配置（使用较小密钥以加快示例速度）
    let mgr = ConfigManager::new();
    let mut cfg = mgr.get_crypto_config();
    cfg.rsa_key_bits = 2048;
    cfg.kyber_parameter_k = 512;
    println!("开始更新默认配置...");
    mgr.update_crypto_config(cfg)?;
    println!("默认配置更新完成");
    println!("开始创建默认配置引擎...");
    let mut engine_default = QSealEngine::<PostQuantumKyber>::new(Arc::new(mgr), "example_keys")?;
    println!("默认配置引擎创建完成");
    println!("开始默认配置 encrypt...");
    let cipher1 = engine_default.encrypt(data)?;
    println!("默认配置 encrypt 完成");
    println!("开始默认配置 decrypt...");
    let plain1 = engine_default.decrypt(&cipher1)?;
    println!("默认配置 decrypt 完成");
    assert_eq!(plain1, data);
    println!("[默认配置] 解密成功: {:?}", String::from_utf8_lossy(&plain1));
    // 清理第一种方法生成的密钥目录
    let _ = fs::remove_dir_all("./keys");

    // 方法二：JSON 配置文件
    println!("\n[方法二：JSON 配置开始]");
    // 在使用 JSON 存储前删除旧目录，确保干净
    let _ = fs::remove_dir_all("example_keys_file");
    // 写入 JSON 配置文件
    let json = r#"
    {
      "crypto": {
        "use_traditional": true,
        "use_post_quantum": true,
        "rsa_key_bits": 2048,
        "kyber_parameter_k": 768,
        "use_authenticated_encryption": true,
        "auto_verify_signatures": true,
        "default_signature_algorithm": "RSA-PSS-SHA256",
        "argon2_memory_cost": 19456,
        "argon2_time_cost": 2
      },
      "rotation": {
        "validity_period_days": 90,
        "max_usage_count": 10000,
        "rotation_start_days": 7
      },
      "storage": {
        "key_storage_dir": "./example_keys_file",
        "use_metadata_cache": true,
        "secure_delete": true,
        "file_permissions": 384
      }
    }"#;
    println!("正在写入 config.json...");
    fs::write("config.json", json)?;
    println!("config.json 写入完成");

    println!("开始创建 JSON 文件配置引擎...");
    let mut engine_file = QSealEngine::<PostQuantumKyber>::from_file("config.json", "example_keys")?;
    println!("JSON 引擎创建完成");
    let cipher2 = engine_file.encrypt(data)?;
    println!("JSON 引擎 encrypt 完成");
    let plain2 = engine_file.decrypt(&cipher2)?;
    println!("JSON 引擎 decrypt 完成");
    assert_eq!(plain2, data);
    println!("[文件配置] 解密成功: {:?}", String::from_utf8_lossy(&plain2));
    // 清理第二种方法生成的密钥目录和配置文件
    let _ = fs::remove_dir_all("example_keys_file");
    let _ = fs::remove_file("config.json");

    // 方法三：环境变量配置
    println!("\n[方法三：环境变量配置开始]");
    println!("设置环境变量...");
    unsafe {
        std::env::set_var("Q_SEAL_RSA_BITS", "4096");
        std::env::set_var("Q_SEAL_KYBER_PARAMETER_K", "512");
    }
    println!("环境变量设置完成");
    println!("开始创建环境变量配置引擎...");
    let config_env = Arc::new(ConfigManager::from_env());
    let mut engine_env = QSealEngine::<PostQuantumKyber>::new(config_env, "example_keys")?;
    println!("环境变量配置引擎创建完成");
    println!("开始环境变量 encrypt...");
    let cipher3 = engine_env.encrypt(data)?;
    println!("环境变量 encrypt 完成");
    println!("开始环境变量 decrypt...");
    let plain3 = engine_env.decrypt(&cipher3)?;
    println!("环境变量 decrypt 完成");
    assert_eq!(plain3, data);
    println!("[环境变量配置] 解密成功: {:?}", String::from_utf8_lossy(&plain3));
    // 清理第三种方法生成的密钥目录
    let _ = fs::remove_dir_all("./keys");

    Ok(())
} 
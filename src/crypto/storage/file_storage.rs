use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use dashmap::DashMap;

use crate::crypto::traits::KeyMetadata;
use crate::crypto::key_rotation::KeyStorage;
use crate::crypto::errors::Error;

// 以下仅在启用 secure-storage 特性时可用
#[cfg(feature = "secure-storage")]
use crate::crypto::traits::SecureKeyStorage;
#[cfg(feature = "secure-storage")]
use crate::crypto::storage::encrypted_container::EncryptedKeyContainer;

/// 密钥文件存储
/// 
/// 提供密钥的文件系统持久化能力，同时支持加密容器和密钥轮换
pub struct KeyFileStorage {
    /// 密钥存储目录
    storage_dir: PathBuf,
    /// 元数据缓存
    metadata_cache: DashMap<String, KeyMetadata>,
}

impl KeyFileStorage {
    /// 创建新的密钥文件存储
    /// 
    /// # 参数
    /// 
    /// * `storage_dir` - 存储密钥文件的目录
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Result<Self, Error> {
        let path = storage_dir.as_ref().to_path_buf();
        
        // 确保目录存在
        fs::create_dir_all(&path)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("无法创建密钥存储目录 {}: {}", path.display(), e)
            )))?;
        
        Ok(Self { 
            storage_dir: path,
            metadata_cache: DashMap::new(),
        })
    }
    
    /// 保存加密的密钥容器
    /// 
    /// # 参数
    /// 
    /// * `name` - 密钥名称
    /// * `container` - 加密的密钥容器
    #[cfg(feature = "secure-storage")]
    pub fn save_container(&self, name: &str, container: &EncryptedKeyContainer) -> Result<(), Error> {
        let file_path = self.get_container_path(name);
        let json = container.to_json()?;
        
        let mut file = File::create(&file_path)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("无法创建密钥文件 {}: {}", file_path.display(), e)
            )))?;
        
        file.write_all(json.as_bytes())
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("写入密钥文件失败 {}: {}", file_path.display(), e)
            )))?;
        
        Ok(())
    }
    
    /// 加载加密的密钥容器
    /// 
    /// # 参数
    /// 
    /// * `name` - 密钥名称
    #[cfg(feature = "secure-storage")]
    pub fn load_container(&self, name: &str) -> Result<EncryptedKeyContainer, Error> {
        let file_path = self.get_container_path(name);
        
        let mut file = File::open(&file_path)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("无法打开密钥文件 {}: {}", file_path.display(), e)
            )))?;
        
        let mut json = String::new();
        file.read_to_string(&mut json)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取密钥文件失败 {}: {}", file_path.display(), e)
            )))?;
        
        <EncryptedKeyContainer as SecureKeyStorage>::from_json(&json)
    }
    
    /// 删除密钥文件
    /// 
    /// # 参数
    /// 
    /// * `name` - 密钥名称
    #[cfg(feature = "secure-storage")]
    pub fn delete_container(&self, name: &str) -> Result<(), Error> {
        let file_path = self.get_container_path(name);
        
        if file_path.exists() {
            fs::remove_file(&file_path)
                .map_err(|e| Error::Io(io::Error::new(
                    e.kind(),
                    format!("删除密钥文件失败 {}: {}", file_path.display(), e)
                )))?;
        }
        
        Ok(())
    }
    
    /// 列出所有密钥容器名称
    #[cfg(feature = "secure-storage")]
    pub fn list_containers(&self) -> Result<Vec<String>, Error> {
        let entries = fs::read_dir(&self.storage_dir)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取存储目录失败 {}: {}", self.storage_dir.display(), e)
            )))?;
        
        let mut names = Vec::new();
        
        for entry in entries {
            let entry = entry.map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取目录条目失败: {}", e)
            )))?;
            
            if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".json") && !name.ends_with(".meta.json") {
                        names.push(name.trim_end_matches(".json").to_string());
                    }
                }
            }
        }
        
        Ok(names)
    }
    
    /// 检查密钥容器是否存在
    /// 
    /// # 参数
    /// 
    /// * `name` - 密钥名称
    #[cfg(feature = "secure-storage")]
    pub fn container_exists(&self, name: &str) -> bool {
        self.get_container_path(name).exists()
    }
    
    /// 获取密钥容器文件路径
    #[cfg(feature = "secure-storage")]
    fn get_container_path(&self, name: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.json", name))
    }
    
    /// 获取密钥元数据文件路径
    fn get_metadata_path(&self, name: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.meta.json", name))
    }
    
    /// 获取密钥数据文件路径
    fn get_data_path(&self, name: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.data", name))
    }
    
    /// 加载并缓存所有元数据
    pub fn preload_metadata(&self) -> Result<(), Error> {
        let entries = fs::read_dir(&self.storage_dir)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取存储目录失败 {}: {}", self.storage_dir.display(), e)
            )))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取目录条目失败: {}", e)
            )))?;
            
            let path = entry.path();
            if !path.is_file() || !path.extension().map_or(false, |ext| ext == "json") {
                continue;
            }
            
            let filename = path.file_stem().unwrap().to_str().unwrap();
            if !filename.ends_with(".meta") {
                continue;
            }
            
            let key_name = filename.trim_end_matches(".meta");
            
            // 读取元数据文件
            let mut file = File::open(&path)
                .map_err(|e| Error::Io(io::Error::new(
                    e.kind(),
                    format!("无法打开元数据文件 {}: {}", path.display(), e)
                )))?;
                
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| Error::Io(io::Error::new(
                    e.kind(),
                    format!("读取元数据文件失败 {}: {}", path.display(), e)
                )))?;
                
            // 解析元数据
            let metadata: KeyMetadata = serde_json::from_str(&contents)
                .map_err(|e| Error::Serialization(format!("解析元数据失败: {}", e)))?;
                
            self.metadata_cache.insert(key_name.to_string(), metadata);
        }
        
        Ok(())
    }
}

// 实现KeyStorage接口，支持密钥轮换管理
impl KeyStorage for KeyFileStorage {
    fn save_key(&self, name: &str, metadata: &KeyMetadata, key_data: &[u8]) -> Result<(), Error> {
        // 确保存储目录存在，以防目录被外部删除
        fs::create_dir_all(&self.storage_dir)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("无法创建密钥存储目录 {}: {}", self.storage_dir.display(), e)
            )))?;
        
        // 保存元数据
        let metadata_path = self.get_metadata_path(name);
        let metadata_json = serde_json::to_string_pretty(metadata)
            .map_err(|e| Error::Serialization(format!("序列化元数据失败: {}", e)))?;
            
        let mut meta_file = File::create(&metadata_path)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("无法创建元数据文件 {}: {}", metadata_path.display(), e)
            )))?;
            
        meta_file.write_all(metadata_json.as_bytes())
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("写入元数据文件失败 {}: {}", metadata_path.display(), e)
            )))?;
            
        // 保存密钥数据
        let data_path = self.get_data_path(name);
        let mut data_file = File::create(&data_path)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("无法创建数据文件 {}: {}", data_path.display(), e)
            )))?;
            
        data_file.write_all(key_data)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("写入数据文件失败 {}: {}", data_path.display(), e)
            )))?;
            
        // 更新缓存
        self.metadata_cache.insert(name.to_string(), metadata.clone());
            
        Ok(())
    }
    
    fn load_key(&self, name: &str) -> Result<(KeyMetadata, Vec<u8>), Error> {
        // 先尝试从缓存获取元数据
        let metadata = if let Some(entry) = self.metadata_cache.get(name) {
            entry.clone()
        } else {
            // 如果缓存中没有，从文件读取
            let metadata_path = self.get_metadata_path(name);
            let mut file = File::open(&metadata_path)
                .map_err(|e| Error::Io(io::Error::new(
                    e.kind(),
                    format!("无法打开元数据文件 {}: {}", metadata_path.display(), e)
                )))?;
                
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| Error::Io(io::Error::new(
                    e.kind(),
                    format!("读取元数据文件失败 {}: {}", metadata_path.display(), e)
                )))?;
                
            // 解析元数据
            let metadata: KeyMetadata = serde_json::from_str(&contents)
                .map_err(|e| Error::Serialization(format!("解析元数据失败: {}", e)))?;
                
            // 更新缓存
            self.metadata_cache.insert(name.to_string(), metadata.clone());
            
            metadata
        };
        
        // 读取密钥数据
        let data_path = self.get_data_path(name);
        let mut file = File::open(&data_path)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("无法打开数据文件 {}: {}", data_path.display(), e)
            )))?;
            
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取数据文件失败 {}: {}", data_path.display(), e)
            )))?;
            
        Ok((metadata, data))
    }
    
    fn key_exists(&self, name: &str) -> bool {
        // 先检查缓存
        if self.metadata_cache.contains_key(name) {
            return true;
        }
        
        // 然后检查文件系统
        self.get_metadata_path(name).exists() && self.get_data_path(name).exists()
    }
    
    fn list_keys(&self) -> Result<Vec<String>, Error> {
        let entries = fs::read_dir(&self.storage_dir)
            .map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取存储目录失败 {}: {}", self.storage_dir.display(), e)
            )))?;
        
        let mut names = Vec::new();
        
        for entry in entries {
            let entry = entry.map_err(|e| Error::Io(io::Error::new(
                e.kind(),
                format!("读取目录条目失败: {}", e)
            )))?;
            
            let path = entry.path();
            if !path.is_file() || !path.extension().map_or(false, |ext| ext == "json") {
                continue;
            }
            
            let filename = path.file_stem().unwrap().to_str().unwrap();
            if !filename.ends_with(".meta") {
                continue;
            }
            
            let key_name = filename.trim_end_matches(".meta");
            names.push(key_name.to_string());
        }
        
        Ok(names)
    }
    
    fn delete_key(&self, name: &str) -> Result<(), Error> {
        let metadata_path = self.get_metadata_path(name);
        let data_path = self.get_data_path(name);
        
        // 删除元数据文件
        if metadata_path.exists() {
            fs::remove_file(&metadata_path)
                .map_err(|e| Error::Io(io::Error::new(
                    e.kind(),
                    format!("删除元数据文件失败 {}: {}", metadata_path.display(), e)
                )))?;
        }
        
        // 删除数据文件
        if data_path.exists() {
            fs::remove_file(&data_path)
                .map_err(|e| Error::Io(io::Error::new(
                    e.kind(),
                    format!("删除数据文件失败 {}: {}", data_path.display(), e)
                )))?;
        }
        
        // 从缓存中删除
        self.metadata_cache.remove(name);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 仅在 secure-storage 特性启用时引入 SecretString
    #[cfg(feature = "secure-storage")]
    use secrecy::SecretString;
    use tempfile::tempdir;
    use crate::crypto::traits::KeyStatus;

    #[cfg(feature = "secure-storage")]
    #[test]
    fn key_file_storage_operations() {
        // 创建临时目录
        let temp_dir = tempdir().unwrap();
        let storage = KeyFileStorage::new(temp_dir.path()).unwrap();
        
        // 创建测试密钥
        let password = SecretString::new("test-password".into());
        let key_data = b"test-key-data";
        let container = EncryptedKeyContainer::new(&password, key_data, "test-algo").unwrap();
        
        // 保存密钥
        storage.save_container("test-key", &container).unwrap();
        
        // 检查密钥是否存在
        assert!(storage.container_exists("test-key"));
        
        // 列出密钥
        let keys = storage.list_containers().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "test-key");
        
        // 加载密钥
        let loaded = storage.load_container("test-key").unwrap();
        let decrypted = loaded.decrypt_key(&password).unwrap();
        assert_eq!(decrypted, key_data);
        
        // 删除密钥
        storage.delete_container("test-key").unwrap();
        assert!(!storage.container_exists("test-key"));
    }
    
    #[test]
    fn key_rotation_storage_operations() {
        // 创建临时目录
        let temp_dir = tempdir().unwrap();
        let storage = KeyFileStorage::new(temp_dir.path()).unwrap();
        
        // 创建测试元数据
        let metadata = KeyMetadata {
            id: "test-id".to_string(),
            created_at: "2023-01-01T00:00:00Z".to_string(),
            expires_at: Some("2024-01-01T00:00:00Z".to_string()),
            usage_count: 0,
            status: KeyStatus::Active,
            version: 1,
            algorithm: "TestAlgo".to_string(),
        };
        
        let key_data = b"test-key-data";
        
        // 测试KeyStorage接口
        
        // 保存密钥
        storage.save_key("rotation-key", &metadata, key_data).unwrap();
        
        // 检查密钥是否存在
        assert!(storage.key_exists("rotation-key"));
        
        // 列出密钥
        let keys = storage.list_keys().unwrap();
        assert!(keys.contains(&"rotation-key".to_string()));
        
        // 加载密钥
        let (loaded_metadata, loaded_data) = storage.load_key("rotation-key").unwrap();
        assert_eq!(loaded_metadata.id, metadata.id);
        assert_eq!(loaded_data, key_data);
        
        // 删除密钥
        storage.delete_key("rotation-key").unwrap();
        assert!(!storage.key_exists("rotation-key"));
    }
    
    #[test]
    fn metadata_cache_works() {
        let temp_dir = tempdir().unwrap();
        let storage = KeyFileStorage::new(temp_dir.path()).unwrap();
        
        // 创建测试元数据
        let metadata = KeyMetadata {
            id: "test-id".to_string(),
            created_at: "2023-01-01T00:00:00Z".to_string(),
            expires_at: Some("2024-01-01T00:00:00Z".to_string()),
            usage_count: 0,
            status: KeyStatus::Active,
            version: 1,
            algorithm: "TestAlgo".to_string(),
        };
        
        let key_data = b"test-key-data";
        
        // 保存密钥
        storage.save_key("test-key", &metadata, key_data).unwrap();
        
        // 预加载元数据
        storage.preload_metadata().unwrap();
        
        // 检查缓存
        assert!(storage.metadata_cache.contains_key("test-key"));
        let cached = storage.metadata_cache.get("test-key").unwrap();
        assert_eq!(cached.value().id, metadata.id);
    }
} 
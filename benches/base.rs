use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use crypto_seal::crypto::common::CryptoConfig;
use crypto_seal::{TraditionalRsa, PostQuantumKyber, HybridRsaKyber, QSealEngine};
use crypto_seal::CryptographicSystem;
use crypto_seal::ConfigManager;
use std::sync::Arc;
use std::io::Cursor;
use std::fs;
use crypto_seal::crypto::common::streaming::{StreamingConfig, StreamingCryptoExt};
use rsa::{RsaPrivateKey, Pkcs1v15Encrypt};
use rsa::pkcs8::DecodePrivateKey;
use crypto_seal::crypto::common::from_base64;
use criterion::SamplingMode;

fn bench_rsa(c: &mut Criterion) {
    let mut config = CryptoConfig::default();
    config.rsa_key_bits = 2048;
    let (pk, sk) = TraditionalRsa::generate_keypair(&config).unwrap();
    let data = vec![0u8; 245];
    c.bench_function("TraditionalRsa encrypt 245B", |b| {
        b.iter(|| TraditionalRsa::encrypt(black_box(&pk), black_box(&data), None).unwrap());
    });
    let ciphertext_str = TraditionalRsa::encrypt(&pk, &data, None).unwrap().to_string();
    let ciphertext_bytes = from_base64(&ciphertext_str).unwrap();
    let rsa_priv = RsaPrivateKey::from_pkcs8_der(&sk.0).unwrap();
    c.bench_function("TraditionalRsa raw decrypt 245B", |b| {
        b.iter(|| rsa_priv.decrypt(Pkcs1v15Encrypt, black_box(&ciphertext_bytes)).unwrap());
    });
}

fn bench_kyber(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = PostQuantumKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024];
    c.bench_function("PostQuantumKyber encrypt 1KB", |b| {
        b.iter(|| PostQuantumKyber::encrypt(black_box(&pk), black_box(&data), None).unwrap());
    });
    let ciphertext = PostQuantumKyber::encrypt(&pk, &data, None).unwrap().to_string();
    c.bench_function("PostQuantumKyber decrypt 1KB", |b| {
        b.iter(|| PostQuantumKyber::decrypt(black_box(&sk), black_box(&ciphertext.as_str()), None).unwrap());
    });
}

fn bench_hybrid(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = HybridRsaKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024];
    c.bench_function("HybridRsaKyber encrypt 1KB", |b| {
        b.iter(|| HybridRsaKyber::encrypt(black_box(&pk), black_box(&data), None).unwrap());
    });
    let ciphertext = HybridRsaKyber::encrypt(&pk, &data, None).unwrap().to_string();
    c.bench_function("HybridRsaKyber decrypt 1KB", |b| {
        b.iter(|| HybridRsaKyber::decrypt(black_box(&sk), black_box(&ciphertext.as_str()), None).unwrap());
    });
}

fn bench_engine(c: &mut Criterion) {
    // 在运行前清理旧的密钥，避免因格式变更导致测试失败
    let _ = fs::remove_dir_all("keys");

    let mut engine = QSealEngine::<HybridRsaKyber>::with_defaults("bench_keys").unwrap();
    let data = vec![0u8; 1024];
    c.bench_function("QSealEngine<HybridRsaKyber> encrypt 1KB", |b| {
        b.iter(|| engine.encrypt(black_box(&data)).unwrap());
    });
    let ciphertext = engine.encrypt(&data).unwrap();
    c.bench_function("QSealEngine<HybridRsaKyber> decrypt 1KB", |b| {
        b.iter(|| engine.decrypt(black_box(&ciphertext.as_str())).unwrap());
    });

    // 清理密钥
    let _ = fs::remove_dir_all("keys");

}

fn bench_qseal_rsa(c: &mut Criterion) {
        // 在运行前清理旧的密钥，避免因格式变更导致测试失败
        let _ = fs::remove_dir_all("keys");

    let config_mgr = Arc::new(ConfigManager::new());
    let mut crypto_cfg = config_mgr.get_crypto_config();
    crypto_cfg.rsa_key_bits = 2048;
    config_mgr.update_crypto_config(crypto_cfg).unwrap();
    let mut engine = QSealEngine::<TraditionalRsa>::new(config_mgr, "bench_keys_rsa").unwrap();
    let data = vec![0u8; 245];
    c.bench_function("QSealEngine<TraditionalRsa> encrypt 245B", |b| {
        b.iter(|| engine.encrypt(black_box(&data)).unwrap());
    });
    let ciphertext = engine.encrypt(&data).unwrap();
    c.bench_function("QSealEngine<TraditionalRsa> decrypt 245B", |b| {
        b.iter(|| engine.decrypt(black_box(&ciphertext.as_str())).unwrap());
    });

    // 清理密钥
    let _ = fs::remove_dir_all("keys");
}

fn bench_qseal_kyber(c: &mut Criterion) {
    // 在运行前清理旧的密钥，避免因格式变更导致测试失败
    let _ = fs::remove_dir_all("keys");

    let mut engine = QSealEngine::<PostQuantumKyber>::with_defaults("bench_keys_kyber").unwrap();
    let data = vec![0u8; 1024];
    c.bench_function("QSealEngine<PostQuantumKyber> encrypt 1KB", |b| {
        b.iter(|| engine.encrypt(black_box(&data)).unwrap());
    });
    let ciphertext = engine.encrypt(&data).unwrap();
    c.bench_function("QSealEngine<PostQuantumKyber> decrypt 1KB", |b| {
        b.iter(|| engine.decrypt(black_box(&ciphertext.as_str())).unwrap());
    });

    // 清理密钥
    let _ = fs::remove_dir_all("keys");
}

fn bench_stream_rsa_encrypt(c: &mut Criterion) {
    let mut config = CryptoConfig::default();
    config.rsa_key_bits = 2048;
    let (pk, sk) = TraditionalRsa::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 245;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    c.benchmark_group("Stream")
     .sample_size(10)
     .sampling_mode(SamplingMode::Flat)
     .bench_function("TraditionalRsa encrypt_stream 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            TraditionalRsa::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_rsa_decrypt(c: &mut Criterion) {
    let mut config = CryptoConfig::default();
    config.rsa_key_bits = 2048;
    let (pk, sk) = TraditionalRsa::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 245;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    let mut encrypted = Vec::new();
    TraditionalRsa::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut encrypted), &scfg, None).unwrap();
    c.benchmark_group("Stream")
     .sample_size(10)
     .sampling_mode(SamplingMode::Flat)
     .bench_function("TraditionalRsa decrypt_stream 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            TraditionalRsa::decrypt_stream(&sk, Cursor::new(&encrypted), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_kyber_encrypt(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = PostQuantumKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    c.benchmark_group("Stream")
     .sample_size(10)
     .sampling_mode(SamplingMode::Flat)
     .bench_function("PostQuantumKyber encrypt_stream 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            PostQuantumKyber::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_kyber_decrypt(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = PostQuantumKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    let mut encrypted = Vec::new();
    PostQuantumKyber::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut encrypted), &scfg, None).unwrap();
    c.benchmark_group("Stream")
     .sample_size(10)
     .sampling_mode(SamplingMode::Flat)
     .bench_function("PostQuantumKyber decrypt_stream 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            PostQuantumKyber::decrypt_stream(&sk, Cursor::new(&encrypted), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_hybrid_encrypt(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = HybridRsaKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    c.benchmark_group("Stream")
     .sample_size(10)
     .sampling_mode(SamplingMode::Flat)
     .bench_function("HybridRsaKyber encrypt_stream 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            HybridRsaKyber::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_hybrid_decrypt(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = HybridRsaKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    let mut encrypted = Vec::new();
    HybridRsaKyber::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut encrypted), &scfg, None).unwrap();
    c.benchmark_group("Stream")
     .sample_size(10)
     .sampling_mode(SamplingMode::Flat)
     .bench_function("HybridRsaKyber decrypt_stream 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            HybridRsaKyber::decrypt_stream(&sk, Cursor::new(&encrypted), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

criterion_group!(
    base,
    bench_rsa,
    bench_kyber,
    bench_hybrid,
    bench_engine,
    bench_qseal_rsa,
    bench_qseal_kyber,
    bench_stream_rsa_encrypt,
    bench_stream_rsa_decrypt,
    bench_stream_kyber_encrypt,
    bench_stream_kyber_decrypt,
    bench_stream_hybrid_encrypt,
    bench_stream_hybrid_decrypt
);
criterion_main!(base); 
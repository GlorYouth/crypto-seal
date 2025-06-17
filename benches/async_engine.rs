#![cfg(feature = "async-engine")]
use std::fs;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::sync::Arc;
use seal_kit::AsyncQSealEngine;
use seal_kit::ConfigManager;
use seal_kit::HybridRsaKyber;

fn bench_async_engine_encrypt(c: &mut Criterion) {
    let _ = fs::remove_dir_all("keys");
    let config = Arc::new(ConfigManager::new());
    let engine = AsyncQSealEngine::<HybridRsaKyber>::new(config.clone(), "bench_async").unwrap();
    let data = vec![0u8; 1024];
    c.bench_function("AsyncQSealEngine<HybridRsaKyber> encrypt 1KB", |b| {
        b.iter(|| engine.encrypt(black_box(&data)).unwrap());
    });
    let _ = fs::remove_dir_all("keys");
}

fn bench_async_engine_decrypt(c: &mut Criterion) {
    let _ = fs::remove_dir_all("keys");
    let config = Arc::new(ConfigManager::new());
    let engine = AsyncQSealEngine::<HybridRsaKyber>::new(config.clone(), "bench_async").unwrap();
    let data = vec![0u8; 1024];
    let ciphertext = engine.encrypt(&data).unwrap();
    c.bench_function("AsyncQSealEngine<HybridRsaKyber> decrypt 1KB", |b| {
        b.iter(|| engine.decrypt(black_box(&ciphertext.as_str())).unwrap());
    });
    let _ = fs::remove_dir_all("keys");
}

criterion_group!(async_benches, bench_async_engine_encrypt, bench_async_engine_decrypt);
criterion_main!(async_benches); 
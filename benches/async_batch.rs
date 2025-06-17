#![cfg(all(feature = "async-engine", feature = "parallel"))]

use criterion::{criterion_group, criterion_main, Criterion, black_box};
use std::sync::Arc;
use crypto_seal::AsyncQSealEngine;
use crypto_seal::ConfigManager;
use crypto_seal::HybridRsaKyber;

fn bench_async_engine_batch(c: &mut Criterion) {
    let config = Arc::new(ConfigManager::new());
    let engine = AsyncQSealEngine::<HybridRsaKyber>::new(config, "bench_async_batch").unwrap();
    let batch: Vec<Vec<u8>> = (0..100).map(|_| vec![0u8; 1024]).collect();
    c.bench_function("AsyncQSealEngine encrypt_batch 100x1KB", |b| {
        b.iter(|| engine.encrypt_batch(black_box(&batch)));
    });
}

criterion_group!(async_batch, bench_async_engine_batch);
criterion_main!(async_batch); 
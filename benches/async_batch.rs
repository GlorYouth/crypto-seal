#![cfg(all(feature = "async-engine", feature = "parallel"))]

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::sync::Arc;
use crypto_seal::AsyncQSealEngine;
use crypto_seal::ConfigManager;
use crypto_seal::HybridRsaKyber;

fn bench_async_engine_batch(c: &mut Criterion) {
    let config = Arc::new(ConfigManager::new());
    let engine = AsyncQSealEngine::<HybridRsaKyber>::new(config, "bench_async_batch").unwrap();
    let batch = vec![b"some data".to_vec(); 100];
    c.bench_function("encrypt_batch", |b| {
        b.iter(|| engine.encrypt_batch(black_box(&batch)));
    });
}

criterion_group!(async_batch, bench_async_engine_batch);
criterion_main!(async_batch); 
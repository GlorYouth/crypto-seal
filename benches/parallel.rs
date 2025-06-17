#![cfg(feature = "parallel")]

use criterion::{criterion_group, criterion_main, Criterion};
use seal_kit::primitives::{CryptoConfig, StreamingConfig, encrypt_stream_parallel, decrypt_stream_parallel};
use seal_kit::{TraditionalRsa, PostQuantumKyber, HybridRsaKyber, CryptographicSystem};
use seal_kit::traits::SyncStreamingSystem;
use std::io::Cursor;

fn bench_stream_rsa_encrypt_parallel(c: &mut Criterion) {
    let mut config = CryptoConfig::default();
    config.rsa_key_bits = 2048;
    let (pk, _sk) = TraditionalRsa::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 245;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    c.bench_function("TraditionalRsa encrypt_stream_parallel 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            encrypt_stream_parallel::<TraditionalRsa, _, _>(&pk, Cursor::new(&data), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_rsa_decrypt_parallel(c: &mut Criterion) {
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
    c.bench_function("TraditionalRsa decrypt_stream_parallel 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            decrypt_stream_parallel::<TraditionalRsa, _, _>(&sk, Cursor::new(&encrypted), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_kyber_encrypt_parallel(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, _sk) = PostQuantumKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    c.bench_function("PostQuantumKyber encrypt_stream_parallel 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            encrypt_stream_parallel::<PostQuantumKyber, _, _>(&pk, Cursor::new(&data), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_kyber_decrypt_parallel(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = PostQuantumKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    let mut encrypted = Vec::new();
    PostQuantumKyber::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut encrypted), &scfg, None).unwrap();
    c.bench_function("PostQuantumKyber decrypt_stream_parallel 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            decrypt_stream_parallel::<PostQuantumKyber, _, _>(&sk, Cursor::new(&encrypted), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_hybrid_encrypt_parallel(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, _sk) = HybridRsaKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    c.bench_function("HybridRsaKyber encrypt_stream_parallel 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            encrypt_stream_parallel::<HybridRsaKyber, _, _>(&pk, Cursor::new(&data), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

fn bench_stream_hybrid_decrypt_parallel(c: &mut Criterion) {
    let config = CryptoConfig::default();
    let (pk, sk) = HybridRsaKyber::generate_keypair(&config).unwrap();
    let data = vec![0u8; 1024 * 1024];
    let mut scfg = StreamingConfig::default();
    scfg.buffer_size = 64 * 1024;
    scfg.keep_in_memory = true;
    scfg.total_bytes = Some(data.len() as u64);
    let mut encrypted = Vec::new();
    HybridRsaKyber::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut encrypted), &scfg, None).unwrap();
    c.bench_function("HybridRsaKyber decrypt_stream_parallel 1MB", |b| {
        b.iter(|| {
            let mut writer = Vec::new();
            decrypt_stream_parallel::<HybridRsaKyber, _, _>(&sk, Cursor::new(&encrypted), Cursor::new(&mut writer), &scfg, None).unwrap();
        });
    });
}

criterion_group!(
    parallel_benches,
    bench_stream_rsa_encrypt_parallel,
    bench_stream_rsa_decrypt_parallel,
    bench_stream_kyber_encrypt_parallel,
    bench_stream_kyber_decrypt_parallel,
    bench_stream_hybrid_encrypt_parallel,
    bench_stream_hybrid_decrypt_parallel
);
criterion_main!(parallel_benches);
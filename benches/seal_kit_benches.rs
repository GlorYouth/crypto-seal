use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput, SamplingMode};
use rand::{RngCore};
use seal_kit::common::traits::AsymmetricAlgorithm;
use seal_kit::{Error, Seal, SealMode};
use secrecy::SecretString;
use std::io::Cursor;
use std::sync::Arc;
use tempfile::tempdir;
use std::time::Duration;
use std::hint::black_box;
use criterion::BatchSize;
use std::fs;

const AAD: &[u8] = b"CriterionProfileAAD";

/// Helper function to create a temporary Seal instance.
/// 辅助函数：创建一个临时的 Seal 实例。
fn setup_seal(
    algorithm: AsymmetricAlgorithm,
) -> Result<(Arc<Seal>, SecretString, tempfile::TempDir), Error> {
    let dir = tempdir().map_err(|e| Error::Io(e))?;
    let seal_path = dir.path().join("criterion_seal.seal");
    let password = SecretString::new("criterion-test-password".to_string().into_boxed_str());
    let seal = Seal::create(&seal_path, &password)?;
    seal.rotate_asymmetric_key(algorithm, &password)?;
    Ok((seal, password, dir))
}

fn generate_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::rng().fill_bytes(&mut data);
    data
}

/// The main benchmark function that covers all modes.
/// 覆盖所有模式的主基准测试函数。
fn seal_kit_benchmark(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("benchmark_vault.seal");

    let password = SecretString::new("password".to_string().into_boxed_str());
    let seal = Seal::create(&vault_path, &password).unwrap();

    let mut group = c.benchmark_group("Seal-Kit Performance");
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(Duration::from_secs(15));

    let data_sizes = [
        ("1KB", 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
        ("100MB", 100 * 1024 * 1024),
    ];
    let algorithms = [
        AsymmetricAlgorithm::Rsa2048,
        AsymmetricAlgorithm::Kyber768,
        AsymmetricAlgorithm::RsaKyber768,
    ];

    for alg in algorithms.iter() {
        seal.rotate_asymmetric_key(alg.clone(), &password).unwrap();
        let engine = seal.engine(SealMode::Hybrid, &password).unwrap();

        // --- Standard Encryption Benchmarks ---
        for &(size_name, data_size) in &data_sizes {
            group.throughput(Throughput::Bytes(data_size as u64));
            let data = generate_random_data(data_size);

            // In-Memory
            group.bench_with_input(
                BenchmarkId::new(format!("{:?}-Memory", alg), size_name),
                &data,
                |b, d| {
                    let mut mut_engine = engine.clone();
                    b.iter(|| {
                        black_box(mut_engine.seal_bytes(d, None).unwrap());
                    })
                },
            );

            // In-Memory (Decryption)
            let ciphertext = engine.clone().seal_bytes(&data, None).unwrap();
            group.bench_with_input(
                BenchmarkId::new(format!("{:?}-Memory-Decrypt", alg), size_name),
                &ciphertext,
                |b, c| {
                    let mut mut_engine = engine.clone();
                    b.iter(|| {
                        black_box(mut_engine.unseal_bytes(c, None).unwrap());
                    })
                },
            );

            // Parallel Streaming
            if data_size > 1024 * 1024 { // Only run parallel on larger data
                group.bench_with_input(
                    BenchmarkId::new(format!("{:?}-Parallel-Stream", alg), size_name),
                    &data,
                    |b, d| {
                        let mut mut_engine = engine.clone();
                        b.iter_batched(
                            || (Cursor::new(d.clone()), Vec::new()),
                            |(mut reader, mut writer): (Cursor<Vec<u8>>, Vec<u8>)| {
                                mut_engine.par_seal_stream(&mut reader, &mut writer, None).unwrap();
                                black_box(writer);
                            },
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }

        // --- DEK Caching Benchmarks ---
        #[cfg(feature = "dek-caching")]
        {
            // Create a separate engine for caching tests to not interfere with standard ones
            let mut caching_engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            
            // Pre-warm the cache by performing one small encryption.
            // This calls the internal, private `ensure_dek_cached` implicitly.
            let warm_up_data = [0u8; 16];
            let _ = black_box(
                caching_engine
                    .seal_bytes_with_cached_dek(&warm_up_data, None)
                    .unwrap(),
            );

            for &(size_name, data_size) in &data_sizes {
                group.throughput(Throughput::Bytes(data_size as u64));
                let data = generate_random_data(data_size);

                // In-Memory with cached DEK
                group.bench_with_input(
                    BenchmarkId::new(format!("{:?}-Cached-Memory", alg), size_name),
                    &data,
                    |b, d| {
                        // The engine is already warmed up, so we can reuse it
                        b.iter(|| {
                            black_box(caching_engine.seal_bytes_with_cached_dek(d, None).unwrap());
                        })
                    },
                );
                
                // Parallel Streaming with cached DEK
                if data_size > 1024 * 1024 { // Only run parallel on larger data
                    group.bench_with_input(
                        BenchmarkId::new(format!("{:?}-Cached-Parallel-Stream", alg), size_name),
                        &data,
                        |b, d| {
                            b.iter_batched(
                                || (Cursor::new(d.clone()), Vec::new()),
                                |(mut reader, mut writer): (Cursor<Vec<u8>>, Vec<u8>)| {
                                    caching_engine.par_seal_stream_with_cached_dek(&mut reader, &mut writer, None).unwrap();
                                    black_box(writer);
                                },
                                BatchSize::SmallInput,
                            )
                        },
                    );
                }
            }
        }
    }

    group.finish();
    // tempdir is automatically dropped and cleaned up here, no need for manual file removal.
}

criterion_group!(benches, seal_kit_benchmark);
criterion_main!(benches); 
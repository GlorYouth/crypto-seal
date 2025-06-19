use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use seal_kit::common::traits::AsymmetricAlgorithm;
use seal_kit::{Error, Seal, SealMode};
use secrecy::SecretString;
use std::io::Cursor;
use std::sync::Arc;
use tempfile::tempdir;

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

/// The main benchmark function that covers all modes.
/// 覆盖所有模式的主基准测试函数。
fn seal_kit_benchmark(c: &mut Criterion) {
    let data_sizes = [1024 * 1024, 10 * 1024 * 1024]; // 1MB and 10MB
    let algorithms = [
        AsymmetricAlgorithm::RsaKyber768,
        AsymmetricAlgorithm::Kyber768,
        AsymmetricAlgorithm::Rsa2048,
    ];

    for &size in &data_sizes {
        let mut group = c.benchmark_group(format!("Seal-Kit-Perf-{}B", size));
        group.throughput(Throughput::Bytes(size as u64));

        let data = vec![0x42; size];

        for algo in &algorithms {
            let (seal, password, _dir) = setup_seal(algo.clone()).expect("Failed to setup seal");
            let algo_id = format!("{:?}", algo);

            // --- Pre-generate ciphertexts for decryption tests ---
            // --- 为解密测试预先生成密文 ---
            let (ciphertext_serial, ciphertext_parallel) = {
                let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
                let c1 = engine.seal_bytes(&data, Some(AAD)).unwrap();
                let c2 = engine.par_seal_bytes(&data, Some(AAD)).unwrap();
                (c1, c2)
            };

            // === In-Memory Benchmarks / 内存操作基准测试 ===

            // SealBytes (Serial)
            group.bench_function(BenchmarkId::new(format!("{}-SealBytes", algo_id), size), |b| {
                b.iter_batched(
                    || seal.engine(SealMode::Hybrid, &password).unwrap(),
                    |mut e| e.seal_bytes(&data, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });

            // UnsealBytes (Serial)
            group.bench_function(BenchmarkId::new(format!("{}-UnsealBytes", algo_id), size), |b| {
                b.iter_batched(
                    || seal.engine(SealMode::Hybrid, &password).unwrap(),
                    |e| e.unseal_bytes(&ciphertext_serial, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });

            // ParSealBytes (Parallel)
            group.bench_function(BenchmarkId::new(format!("{}-ParSealBytes", algo_id), size), |b| {
                b.iter_batched(
                    || seal.engine(SealMode::Hybrid, &password).unwrap(),
                    |mut e| e.par_seal_bytes(&data, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });

            // ParUnsealBytes (Parallel)
            group.bench_function(BenchmarkId::new(format!("{}-ParUnsealBytes", algo_id), size), |b| {
                b.iter_batched(
                    || seal.engine(SealMode::Hybrid, &password).unwrap(),
                    |e| e.par_unseal_bytes(&ciphertext_parallel, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });

            // === Streaming Benchmarks / 流操作基准测试 ===

            // SealStream (Serial)
            group.bench_function(BenchmarkId::new(format!("{}-SealStream", algo_id), size), |b| {
                b.iter_batched(
                    || {
                        (
                            seal.engine(SealMode::Hybrid, &password).unwrap(),
                            Cursor::new(data.as_slice()),
                            Vec::with_capacity(size + 1024),
                        )
                    },
                    |(mut e, mut r, mut w)| e.seal_stream(&mut r, &mut w, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });

            // UnsealStream (Serial)
            let stream_ciphertext = {
                let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
                let mut writer = Vec::new();
                engine.seal_stream(&mut Cursor::new(&data), &mut writer, Some(AAD)).unwrap();
                writer
            };
            group.bench_function(BenchmarkId::new(format!("{}-UnsealStream", algo_id), size), |b| {
                b.iter_batched(
                    || {
                        (
                            seal.engine(SealMode::Hybrid, &password).unwrap(),
                            Cursor::new(stream_ciphertext.as_slice()),
                            Vec::with_capacity(size),
                        )
                    },
                    |(e, mut r, mut w)| e.unseal_stream(&mut r, &mut w, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });

            // ParSealStream (Parallel)
            group.bench_function(BenchmarkId::new(format!("{}-ParSealStream", algo_id), size), |b| {
                b.iter_batched(
                    || {
                        (
                            seal.engine(SealMode::Hybrid, &password).unwrap(),
                            Cursor::new(data.as_slice()),
                            Vec::with_capacity(size + 1024),
                        )
                    },
                    |(mut e, r, w)| e.par_seal_stream(r, w, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });

             // ParUnsealStream (Parallel)
             let par_stream_ciphertext = {
                let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
                let mut writer = Vec::new();
                engine.par_seal_stream(Cursor::new(&data), &mut writer, Some(AAD)).unwrap();
                writer
            };
            group.bench_function(BenchmarkId::new(format!("{}-ParUnsealStream", algo_id), size), |b| {
                b.iter_batched(
                    || {
                        (
                            seal.engine(SealMode::Hybrid, &password).unwrap(),
                            Cursor::new(par_stream_ciphertext.as_slice()),
                            Vec::with_capacity(size),
                        )
                    },
                    |(e, r, w)| e.par_unseal_stream(r, w, Some(AAD)),
                    criterion::BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

criterion_group!(benches, seal_kit_benchmark);
criterion_main!(benches); 
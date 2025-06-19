//!
//! 矩阵兼容性测试
//!
//! 这个模块的目的是验证不同加密模式的原始输出之间预期的不兼容性。
//!
mod common;
use crate::common::setup_rsa_kyber_keys;
use seal_kit::{
    asymmetric::{
        traits::AsymmetricParallelStreamingSystem,
        systems::hybrid::rsa_kyber::RsaKyberCryptoSystem,
        traits::AsymmetricParallelSystem,
    },
    symmetric::systems::aes_gcm::AesGcmSystem,
};
use std::io::Cursor;

#[test]
#[cfg(feature = "parallel")]
fn test_par_encrypt_output_incompatible_with_par_decrypt_stream() {
    let (pk, sk) = setup_rsa_kyber_keys();
    let plaintext = vec![0xAB; 4096];

    // 1. 使用内存并行加密方法加密数据
    let ciphertext =
        RsaKyberCryptoSystem::par_encrypt(&pk, &plaintext, &Default::default(), None).unwrap();

    // 2. 尝试使用流式并行解密方法解密 (应失败)
    let mut source = Cursor::new(ciphertext);
    let mut dest = Cursor::new(Vec::new());
    let result = RsaKyberCryptoSystem::par_decrypt_stream::<AesGcmSystem, _, _>(
        &sk,
        &mut source,
        &mut dest,
        &Default::default(),
        &Default::default(),
        None,
    );

    assert!(
        result.is_err(),
        "par_encrypt output should not be decryptable by par_decrypt_stream"
    );
}

#[test]
#[cfg(feature = "parallel")]
fn test_par_stream_encrypt_output_incompatible_with_par_decrypt() {
    let (pk, sk) = setup_rsa_kyber_keys();
    let plaintext = vec![0xCD; 4096];

    // 1. 使用流式并行加密方法加密数据
    let ciphertext = {
        let mut source = Cursor::new(plaintext);
        let mut dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::par_encrypt_stream::<AesGcmSystem, _, _>(
            &pk,
            &mut source,
            &mut dest,
            &Default::default(),
            &Default::default(),
            None,
        )
        .unwrap();
        dest.into_inner()
    };

    // 2. 尝试使用内存并行解密方法解密 (应失败)
    let result = RsaKyberCryptoSystem::par_decrypt(&sk, &ciphertext, &Default::default(), None);

    assert!(
        result.is_err(),
        "par_encrypt_stream output should not be decryptable by par_decrypt"
    );
} 
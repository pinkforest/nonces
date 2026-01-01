use criterion::{black_box, criterion_group, criterion_main, Criterion};

use hex_literal::hex;
use nonces::*;

fn criterion_benchmark(c: &mut Criterion) {

    let iv_bytes: [u8; 12] = hex!("6fac81d4f2c3bebe02b8b375");

    c.bench_function("rustls-nonce", |b| {
        b.iter(|| {
            let iv = Iv::new(&iv_bytes).unwrap();
            let rustls_nonce_1 = Nonce::new(&iv, 1);
        })
    });
    
    c.bench_function("cryto-bigint-nonce", |b| {
        b.iter(|| {
            let crypto_bigint_nonce_1 = CryptoBigInt::seq_nonce(&iv_bytes, black_box(1));
        })
    });
}
    
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);


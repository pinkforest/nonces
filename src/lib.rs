pub const NONCE_LEN: usize = 12;

#[derive(Debug)]
#[allow(dead_code)]
pub enum ApiMisuse {
    IvLengthExceedsMaximum { actual: usize, maximum: usize },
    NonceArraySizeMismatch { expected: usize, actual: usize },    
}

/// A write or read IV.
#[derive(Default, Clone)]
pub struct Iv {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

pub(crate) fn put_u64(v: u64, bytes: &mut [u8]) {
    let bytes: &mut [u8; 8] = (&mut bytes[..8]).try_into().unwrap();
    *bytes = u64::to_be_bytes(v);
}

#[derive(Debug)]
pub enum Error {
    Api(ApiMisuse),
}

impl From<ApiMisuse> for Error {
    fn from(m: ApiMisuse) -> Self {
        Self::Api(m)
    }
}

impl Iv {
    /// Create a new `Iv` from a byte slice.
    ///
    /// Returns an error if the length of `value` exceeds [`Self::MAX_LEN`].
    pub fn new(value: &[u8]) -> Result<Self, Error> {
        if value.len() > Self::MAX_LEN {
            return Err(ApiMisuse::IvLengthExceedsMaximum {
                actual: value.len(),
                maximum: Self::MAX_LEN,
            }
            .into());
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..value.len()].copy_from_slice(value);
        Ok(Self {
            buf,
            used: value.len(),
        })
    }

    /// Return the IV length.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.used
    }

    /// Maximum supported IV length.
    pub const MAX_LEN: usize = 16;
}

impl From<[u8; NONCE_LEN]> for Iv {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Self::new(&bytes).expect("NONCE_LEN is within MAX_LEN")
    }
}

impl AsRef<[u8]> for Iv {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A nonce.  This is unique for all messages on a connection.
pub struct Nonce {
    buf: [u8; Iv::MAX_LEN],
    len: usize,
}

impl Nonce {
    /// Combine an `Iv` and sequence number to produce a unique nonce.
    ///
    /// This is `iv ^ seq` where `seq` is encoded as a big-endian integer.
    #[inline]
    pub fn new(iv: &Iv, seq: u64) -> Self {
        Self::new_inner(None, iv, seq)
    }

    /// Creates a unique nonce based on the multipath `path_id`, the `iv` and packet number `pn`.
    ///
    /// The nonce is computed as the XOR between the `iv` and the big-endian integer formed
    /// by concatenating `path_id` (or 0) and `pn`.
    pub fn quic(path_id: Option<u32>, iv: &Iv, pn: u64) -> Self {
        Self::new_inner(path_id, iv, pn)
    }

    /// Creates a unique nonce based on the iv and sequence number seq.
    #[inline]
    fn new_inner(path_id: Option<u32>, iv: &Iv, seq: u64) -> Self {
        let iv_len = iv.len();
        let mut buf = [0u8; Iv::MAX_LEN];

        if iv_len >= 8 {
            put_u64(seq, &mut buf[iv_len - 8..iv_len]);
            if let Some(path_id) = path_id {
                if iv_len >= 12 {
                    buf[iv_len - 12..iv_len - 8].copy_from_slice(&path_id.to_be_bytes());
                }
            }
        } else {
            let seq_bytes = seq.to_be_bytes();
            buf[..iv_len].copy_from_slice(&seq_bytes[8 - iv_len..]);
        }

        buf[..iv_len]
            .iter_mut()
            .zip(iv.as_ref())
            .for_each(|(s, iv)| *s ^= *iv);

        Self { buf, len: iv_len }
    }

    /// Convert to a fixed-size array of length `N`.
    ///
    /// Returns an error if the nonce length is not `N`.
    ///
    /// For standard nonces, use `nonce.to_array::<NONCE_LEN>()?` or just `nonce.to_array()?`
    /// which defaults to `NONCE_LEN`.
    pub fn to_array<const N: usize>(&self) -> Result<[u8; N], Error> {
        if self.len != N {
            return Err(ApiMisuse::NonceArraySizeMismatch {
                expected: N,
                actual: self.len,
            }
            .into());
        }
        Ok(self.buf[..N]
            .try_into()
            .expect("nonce buffer conversion failed"))
    }

    /// Return the nonce value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the nonce length.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }
}

use crypto_bigint::Encoding;

pub struct CryptoBigInt;

impl CryptoBigInt {

    pub fn seq_nonce(iv_bytes: &[u8; 12], seq_id: u64) -> [u8; 12] {
        let mut u128_iv: [u8; 16] = [0; 16];
        u128_iv[4..16].copy_from_slice(iv_bytes);
        let iv_u128 = crypto_bigint::U128::from_be_bytes(u128_iv);
        let seq_no_u128 = crypto_bigint::U128::from_u64(seq_id);
        let nonce_u128 = iv_u128.wrapping_xor(&seq_no_u128);
        let b: [u8; 16] = nonce_u128.to_be_bytes();
        [b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use hex_literal::hex;
    
    #[test]
    fn compat() {
        let iv_bytes: [u8; 12] = hex!("6fac81d4f2c3bebe02b8b375");
        
        let iv = Iv::new(&iv_bytes).unwrap();        
        let rustls_nonce_1 = Nonce::new(&iv, 1);
        
        let crypto_bigint_nonce_1 = CryptoBigInt::seq_nonce(&iv_bytes, 1);
        
        assert_eq!(rustls_nonce_1.as_bytes(), &crypto_bigint_nonce_1);

        assert_eq!(&crypto_bigint_nonce_1, &hex!("6fac81d4f2c3bebe02b8b374"));
        
    }
}


//! A type-safe, oxidized version of the NaCl API.

use hacl_sys as hacl;
use rand::Rng;
use rand::os::OsRng;

use super::error as crypto;
use super::error::CryptoError::*;

// Constants are all taken from HACL*'s NaCl.c
const CRYPTO_BOX_PUBLIC_KEY_SIZE: usize = 32;
const CRYPTO_BOX_SECRET_KEY_SIZE: usize = 32;
const CRYPTO_BOX_NONCE_SIZE: usize = 24;
const CRYPTO_BOX_BEFORENM_SIZE: usize = 32;
const CRYPTO_BOX_MACBYTES: usize = 16;
const CRYPTO_BOX_ZEROBYTES: usize = 32;
const CRYPTO_SECRETBOX_KEY_SIZE: usize = 32;
const CRYPTO_SECRETBOX_NONCE_SIZE: usize = 24;
const CRYPTO_SECRETBOX_MACBYTES: usize = 16;

/// A cryptographic key, public or private.
#[derive(Debug)]
pub struct Key {
    inner: Vec<u8>,
}

impl Key {
    pub fn new_keypair() -> crypto::Result<(Key, Key)> {
        crypto_box_keypair()
    }

    /// Creates a new empty key with the internal capacity set to the given size.
    fn empty(size: usize) -> Key {
        Key {
            inner: vec![0; size],
        }
    }

    /// Generates a new randomized key of the specified size using the operating system's CSPRNG
    /// via the `rand` crate. Subsequently, it inherits `rand`'s implementation details.
    fn random(size: usize) -> crypto::Result<Key> {
        OsRng::new().map(|mut rng| {
            Key {
                inner: rng.gen_iter().take(size).collect(),
            }
        }).map_err(|e| e.into())
    }

    /// Gets the size of this specific key.
    fn size(&self) -> usize {
        self.inner.len()
    }
}

/// Generates a new random secret key and the corresponding public key, and returns them as the pair
/// (public key, secret key).
pub fn crypto_box_keypair() -> crypto::Result<(Key, Key)> {
    Key::random(CRYPTO_BOX_SECRET_KEY_SIZE).map(|secret_key| {
        let mut public_key = Key::empty(CRYPTO_BOX_PUBLIC_KEY_SIZE);
        let mut basepoint = [0; 32];
        basepoint[0] = 9;

        unsafe {
            hacl::Hacl_Curve25519_crypto_scalarmult(
                public_key.inner.as_mut_ptr(),
                secret_key.inner.as_ptr(),
                basepoint.as_ptr(),
            )
        }

        (public_key, secret_key)
    })
}

/// A message, cleartext or encrypted.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    inner: Vec<u8>,
}

impl Message {
    fn from_bytes(bytes: &[u8]) -> Message {
        Message {
            inner: vec![0; CRYPTO_BOX_ZEROBYTES]
                .iter()
                .chain(bytes.into_iter())
                .map(|x| *x)
                .collect(),
        }
    }

    fn empty(size: usize) -> Message {
        Message {
            inner: vec![0; size],
        }
    }
}

/// A cryptographic nonce, and as such, should only be used once.
#[derive(Clone, Debug)]
pub struct Nonce {
    inner: Vec<u8>,
}

impl Nonce {
    /// Generates a random nonce of the specifized size. The size provided ought to be large enough
    /// that the probability of a collision is negligible.
    pub fn random(size: usize) -> crypto::Result<Nonce> {
        OsRng::new().map(|mut rng| {
            Nonce {
                inner: rng.gen_iter().take(size).collect(),
            }
        }).map_err(|e| e.into())
    }
}

/// Encrypts and authenticates the given message using the given nonce, the receiver's public key,
/// and the sender's secret key.
pub fn crypto_box(message: &Message, nonce: &Nonce, public_key: &Key, secret_key: &Key) -> Message {
    assert_eq!(secret_key.size(), CRYPTO_BOX_SECRET_KEY_SIZE);
    assert_eq!(public_key.size(), CRYPTO_BOX_PUBLIC_KEY_SIZE);
    assert_eq!(nonce.inner.len(), CRYPTO_BOX_NONCE_SIZE);
    let mut ciphertext = Message::empty(message.inner.len());

    unsafe {
        let res = hacl::NaCl_crypto_box_easy(
            ciphertext.inner.as_mut_ptr(),
            message.inner.as_ptr(),
            (message.inner.len() - CRYPTO_BOX_ZEROBYTES) as u64,
            nonce.inner.as_ptr(),
            public_key.inner.as_ptr(),
            secret_key.inner.as_ptr(),
        );

        // According to NaCl API, this should always return 0.
        assert_eq!(res, 0);
    }

    ciphertext
}

/// Verifies and decrypts the given ciphertext using the given nonce, the sender's public key, and
/// the receiver's secret key.
pub fn crypto_box_open(
    ciphertext: &Message, nonce: &Nonce, public_key: &Key, secret_key: &Key
) -> crypto::Result<Message> {
    assert_eq!(secret_key.size(), CRYPTO_BOX_SECRET_KEY_SIZE);
    assert_eq!(public_key.size(), CRYPTO_BOX_PUBLIC_KEY_SIZE);
    assert_eq!(nonce.inner.len(), CRYPTO_BOX_NONCE_SIZE);
    let mut message = Message::empty(ciphertext.inner.len());

    unsafe {
        let res = hacl::NaCl_crypto_box_open_easy(
            message.inner.as_mut_ptr(),
            ciphertext.inner.as_ptr(),
            (ciphertext.inner.len() - CRYPTO_BOX_ZEROBYTES) as u64,
            nonce.inner.as_ptr(),
            public_key.inner.as_ptr(),
            secret_key.inner.as_ptr(),
        );

        if res != 0 {
            bail!(VerificationFailed)
        }
    }

    Ok(message)
}

/// A cryptobox abstraction for authenticated encryption.
#[derive(Debug)]
pub struct CryptoBox {
    shared_key: Key,
}

pub fn crypto_box_beforenm(public_key: Key, secret_key: Key) -> CryptoBox {
    assert_eq!(secret_key.size(), CRYPTO_BOX_SECRET_KEY_SIZE);
    assert_eq!(public_key.size(), CRYPTO_BOX_PUBLIC_KEY_SIZE);
    let mut shared_key = Key::empty(CRYPTO_BOX_BEFORENM_SIZE);

    unsafe {
        let res = hacl::NaCl_crypto_box_beforenm(
            shared_key.inner.as_mut_ptr(),
            public_key.inner.as_ptr(),
            secret_key.inner.as_ptr(),
        );

        assert_eq!(res, 0);
    }

    CryptoBox {
        shared_key: shared_key,
    }
}

pub fn crypto_box_afternm(message: &Message, nonce: &Nonce, cbox: &CryptoBox) -> Message {
    assert_eq!(cbox.shared_key.size(), CRYPTO_BOX_BEFORENM_SIZE);
    assert_eq!(nonce.inner.len(), CRYPTO_BOX_NONCE_SIZE);
    let mut ciphertext = Message::empty(message.inner.len());

    unsafe {
        let res = hacl::NaCl_crypto_box_easy_afternm(
            ciphertext.inner.as_mut_ptr(),
            message.inner.as_ptr(),
            message.inner.len() as u64,
            nonce.inner.as_ptr(),
            cbox.shared_key.inner.as_ptr(),
        );

        assert_eq!(res, 0);
    }

    ciphertext
}

pub fn crypto_box_open_afternm(
    ciphertext: &Message, nonce: &Nonce, cbox: &CryptoBox
) -> crypto::Result<Message> {
    assert_eq!(cbox.shared_key.size(), CRYPTO_BOX_BEFORENM_SIZE);
    assert_eq!(nonce.inner.len(), CRYPTO_BOX_NONCE_SIZE);
    let mut message = Message::empty(ciphertext.inner.len());

    unsafe {
        let res = hacl::NaCl_crypto_box_open_easy_afternm(
            message.inner.as_mut_ptr(),
            ciphertext.inner.as_ptr(),
            ciphertext.inner.len() as u64,
            nonce.inner.as_ptr(),
            cbox.shared_key.inner.as_ptr(),
        );

        if res != 0 {
            bail!(VerificationFailed)
        }
    }

    Ok(message)
}

impl CryptoBox {
    pub fn new(public_key: Key, secret_key: Key) -> CryptoBox {
        crypto_box_beforenm(public_key, secret_key)
    }

    pub fn seal(&self, message: &Message, nonce: &Nonce) -> Message {
        crypto_box_afternm(message, nonce, self)
    }

    pub fn open(&self, ciphertext: &Message, nonce: &Nonce) -> crypto::Result<Message> {
        crypto_box_open_afternm(ciphertext, nonce, self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn one_time_crypto_box_aead() {
        let (alice_public_key, alice_secret_key) = Key::new_keypair().unwrap();
        let (bob_public_key, bob_secret_key) = Key::new_keypair().unwrap();

        let message = Message::from_bytes(b"Hello, Bob");
        println!("M: {:?}", message);
        let nonce = Nonce::random(CRYPTO_BOX_NONCE_SIZE).unwrap();
        println!("N: {:?}", nonce);
        let ciphertext = crypto_box(&message, &nonce, &bob_public_key, &alice_secret_key);
        println!("C: {:?}", ciphertext);
        let verified_message = crypto_box_open(
            &ciphertext, &nonce, &alice_public_key, &bob_secret_key
        ).unwrap();

        assert_eq!(message, verified_message);
    }

    #[test]
    fn crypto_box_aead() {
        let (alice_public_key, alice_secret_key) = Key::new_keypair().unwrap();
        let (bob_public_key, bob_secret_key) = Key::new_keypair().unwrap();
        let alice_box = CryptoBox::new(bob_public_key, alice_secret_key);
        let bob_box = CryptoBox::new(alice_public_key, bob_secret_key);

        let message = Message::from_bytes(b"Hello, Bob");
        println!("M: {:?}", message);
        let nonce = Nonce::random(CRYPTO_BOX_NONCE_SIZE).unwrap();
        println!("N: {:?}", nonce);
        let ciphertext = alice_box.seal(&message, &nonce);
        println!("C: {:?}", ciphertext);
        let verified_message = bob_box.open(&ciphertext, &nonce).unwrap();

        assert_eq!(message, verified_message);
    }
}

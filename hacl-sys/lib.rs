// Hacl_Chacha20.h
extern {
    pub fn Hacl_Chacha20_chacha20(
        output: *const u8, plain: *const u8, len: u32, k: *const u8, n1: *const u8, ctr: u32,
    );
}

// Hacl_Chacha20Poly1305.h
extern {
    pub fn Hacl_Chacha20Poly1305_aead_encrypt(
        c: *const u8, mac: *const u8, m: *const u8, mlen: u32, aad1: *const u8, aadlen: u32,
        k1: *const u8, n1: *const u8,
    );

    pub fn Hacl_Chacha20Poly1305_aead_decrypt(
        m: *const u8, c: *const u8, mlen: u32, mac: *const u8, aad1: *const u8, aadlen: u32,
        k1: *const u8, n1: *const u8,
    );
}

// Hacl_Chacha20_Vec128.h
extern {
    pub fn Hacl_Chacha20_Vec128_chacha20(
        output: *const u8, plain: *const u8, len: u32, k: *const u8, n1: *const u8, ctr: u32,
    );
}

// Hacl_Curve25519.h
extern {
    pub fn Hacl_EC_crypto_scalarmult(mypublic: *const u8, secret: *const u8, basepoint: *const u8);

    pub fn Hacl_Curve25519_crypto_scalarmult(
        mypublic: *const u8, secret: *const u8, basepoint: *const u8,
    );
}

// Hacl_Ed25519.h
extern {
    pub fn Hacl_Ed25519_sign(signature: *const u8, secret: *const u8, msg: *const u8, len1: u32);

    pub fn Hacl_Ed25519_verify(
        public: *const u8, msg: *const u8, len1: u32, signature: *const u8
    ) -> bool;

    pub fn Hacl_Ed25519_secret_to_public(out: *const u8, secret: *const u8);
}

// Hacl_HMAC_SHA2_256.h
extern {
    pub fn hmac_core(mac: *const u8, key: *const u8, data: *const u8, len: u32);

    pub fn hmac(mac: *const u8, key: *const u8, keylen: u32, data: *const u8, datalen: u32);
}


// Hacl_Poly1305_64.h
extern {
    pub fn Hacl_Poly1305_64_crypto_onetimeauth(
        output: *const u8, input: *const u8, len1: u64, k1: *const u8
    );
}

// Hacl_SHA2_256.h
extern {
    pub fn Hacl_SHA2_256_hash(hash1: *const u8, input: *const u8, len: u32);
}

// Hacl_SHA2_384.h
extern {
    pub fn Hacl_SHA2_384_hash(hash1: *const u8, input: *const u8, len: u32);
}

// Hacl_SHA2_512.h
extern {
    pub fn Hacl_SHA2_512_hash(hash1: *const u8, input: *const u8, len: u32);
}

// Hacl_Salsa20.h
extern {
    pub fn Hacl_Salsa20_salsa20(
        output: *const u8, plain: *const u8, len: u32, k: *const u8, n1: *const u8, ctr: u64,
    );

    pub fn Hacl_Salsa20_hsalsa20(output: *const u8, key: *const u8, nonce: *const u8);
}

// NaCl.h
extern {
    pub static NaCl_crypto_box_NONCEBYTES: u32;
    pub static NaCl_crypto_box_PUBLICKEYBYTES: u32;
    pub static NaCl_crypto_box_SECRETKEYBYTES: u32;
    pub static NaCl_crypto_box_MACBYTES: u32;
    pub static NaCl_crypto_secretbox_NONCEBYTES: u32;
    pub static NaCl_crypto_secretbox_KEYBYTES: u32;
    pub static NaCl_crypto_secretbox_MACBYTES: u32;

    pub fn NaCl_crypto_secretbox_detached(
        c: *const u8, mac: *const u8, m: *const u8, mlen: u64, n1: *const u8, k1: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_secretbox_open_detached(
        m: *const u8, c: *const u8, mac: *const u8, clen: u64, n1: *const u8, k1: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_secretbox_easy(
        c: *const u8, m: *const u8, mlen: u64, n1: *const u8, k1: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_secretbox_open_easy(
        m: *const u8, c: *const u8, clen: u64, n1: *const u8, k1: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_box_beforenm(k1: *const u8, pk: *const u8, sk: *const u8) -> u32;

    pub fn NaCl_crypto_box_detached_afternm(
        c: *const u8, mac: *const u8, m: *const u8, mlen: u64, n1: *const u8, k1: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_box_detached(
        c: *const u8, mac: *const u8, m: *const u8, mlen: u64, n1: *const u8, pk: *const u8,
        sk: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_box_open_detached(
        m: *const u8, c: *const u8, mac: *const u8, mlen: u64, n1: *const u8, pk: *const u8,
        sk: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_box_easy_afternm(
        c: *const u8, m: *const u8, mlen: u64, n1: *const u8, k1: *const u8
    ) -> u32;

    pub fn NaCl_crypto_box_easy(
        c: *const u8, m: *const u8, mlen: u64, n1: *const u8, pk: *const u8, sk: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_box_open_easy(
        m: *const u8, c: *const u8, mlen: u64, n1: *const u8, pk: *const u8, sk: *const u8
    ) -> u32;

    pub fn NaCl_crypto_box_open_detached_afternm(
        m: *const u8, c: *const u8, mac: *const u8, mlen: u64, n1: *const u8, k1: *const u8,
    ) -> u32;

    pub fn NaCl_crypto_box_open_easy_afternm(
        m: *const u8, c: *const u8, mlen: u64, n1: *const u8, k1: *const u8,
    ) -> u32;
}

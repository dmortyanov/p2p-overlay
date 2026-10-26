#include "security/crypto_utils.hpp"

#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace p2p::security {

namespace {

void ensure_sodium_initialized() {
    static const bool initialized = []() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        return true;
    }();
    (void)initialized;
}

} // namespace

X25519Keypair X25519Keypair::generate() {
    ensure_sodium_initialized();
    X25519Keypair kp;
    randombytes_buf(kp.secret_key.data(), kp.secret_key.size());
    if (crypto_scalarmult_base(kp.public_key.data(), kp.secret_key.data()) != 0) {
        throw std::runtime_error("Failed to generate X25519 public key");
    }
    return kp;
}

X25519Keypair::~X25519Keypair() {
    sodium_memzero(secret_key.data(), secret_key.size());
}

std::optional<std::array<uint8_t, 32>> x25519_diffie_hellman(
    const std::array<uint8_t, X25519_KEY_SIZE>& my_secret_key,
    const std::array<uint8_t, X25519_KEY_SIZE>& peer_public_key) {
    ensure_sodium_initialized();
    std::array<uint8_t, 32> shared_secret{};
    if (crypto_scalarmult(shared_secret.data(), my_secret_key.data(), peer_public_key.data()) != 0) {
        return std::nullopt;
    }

    // Check if shared secret is all zeros (reject weak keys)
    uint8_t diff = 0;
    for (uint8_t b : shared_secret) {
        diff |= b;
    }
    if (diff == 0) {
        return std::nullopt;
    }

    return shared_secret;
}

std::array<uint8_t, NONCE_SIZE> generate_nonce() {
    ensure_sodium_initialized();
    std::array<uint8_t, NONCE_SIZE> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

std::array<uint8_t, 32> hmac_sha256(
    const uint8_t* key, std::size_t key_len,
    const uint8_t* data, std::size_t data_len) {
    ensure_sodium_initialized();
    std::array<uint8_t, 32> out{};
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    if (data && data_len > 0) {
        crypto_auth_hmacsha256_update(&state, data, data_len);
    }
    crypto_auth_hmacsha256_final(&state, out.data());
    return out;
}

std::array<uint8_t, 32> hkdf_extract(
    const uint8_t* salt, std::size_t salt_len,
    const uint8_t* ikm, std::size_t ikm_len) {
    // RFC 5869: If salt is not provided, it is set to a string of HashLen zeros
    static const std::array<uint8_t, 32> default_salt{};
    const uint8_t* effective_salt = salt ? salt : default_salt.data();
    std::size_t effective_salt_len = salt ? salt_len : default_salt.size();

    // PRK = HMAC-Hash(salt, IKM)
    return hmac_sha256(effective_salt, effective_salt_len, ikm, ikm_len);
}

Bytes hkdf_expand(
    const std::array<uint8_t, 32>& prk,
    std::string_view info,
    std::size_t length) {
    if (length > 255 * 32) {
        throw std::invalid_argument("HKDF-Expand requested length too large");
    }

    Bytes okm;
    okm.reserve(length);

    std::array<uint8_t, 32> t_prev{};
    std::size_t t_prev_len = 0;
    uint8_t counter = 1;

    while (okm.size() < length) {
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, prk.data(), prk.size());
        if (t_prev_len > 0) {
            crypto_auth_hmacsha256_update(&state, t_prev.data(), t_prev_len);
        }
        if (!info.empty()) {
            crypto_auth_hmacsha256_update(&state, reinterpret_cast<const uint8_t*>(info.data()), info.size());
        }
        crypto_auth_hmacsha256_update(&state, &counter, 1);
        crypto_auth_hmacsha256_final(&state, t_prev.data());
        t_prev_len = t_prev.size();

        std::size_t to_copy = std::min(length - okm.size(), t_prev.size());
        okm.insert(okm.end(), t_prev.begin(), t_prev.begin() + to_copy);
        counter++;
    }

    return okm;
}

SessionKeys derive_session_keys(
    const std::array<uint8_t, 32>& shared_secret,
    const std::array<uint8_t, NONCE_SIZE>& nonce_a,
    const std::array<uint8_t, NONCE_SIZE>& nonce_b) {
    // Salt = nonce_a || nonce_b (64 bytes)
    std::array<uint8_t, 64> salt{};
    std::memcpy(salt.data(), nonce_a.data(), 32);
    std::memcpy(salt.data() + 32, nonce_b.data(), 32);

    auto prk = hkdf_extract(salt.data(), salt.size(), shared_secret.data(), shared_secret.size());

    // Expand to 64 bytes: 32 bytes for A->B, 32 bytes for B->A
    auto okm = hkdf_expand(prk, "p2p-ake-session-keys-v1", 64);

    SessionKeys keys;
    std::memcpy(keys.key_a_to_b.data(), okm.data(), 32);
    std::memcpy(keys.key_b_to_a.data(), okm.data() + 32, 32);
    return keys;
}

std::array<uint8_t, AEAD_NONCE_SIZE> construct_aead_nonce(uint64_t seq) {
    std::array<uint8_t, AEAD_NONCE_SIZE> nonce{};
    // First 4 bytes remain zero (prefix / constant)
    // Last 8 bytes: big-endian uint64
    for (int i = 7; i >= 0; --i) {
        nonce[4 + i] = static_cast<uint8_t>(seq & 0xFF);
        seq >>= 8;
    }
    return nonce;
}

Bytes chacha20_poly1305_encrypt(
    const uint8_t* plaintext, std::size_t plaintext_len,
    const uint8_t* aad, std::size_t aad_len,
    const std::array<uint8_t, AEAD_NONCE_SIZE>& nonce,
    const std::array<uint8_t, AEAD_KEY_SIZE>& key) {
    ensure_sodium_initialized();
    Bytes out(plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;

    int res = crypto_aead_chacha20poly1305_ietf_encrypt(
        out.data(), &clen,
        plaintext, plaintext_len,
        aad, aad_len,
        nullptr,
        nonce.data(),
        key.data()
    );

    if (res != 0) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
    }

    out.resize(clen);
    return out;
}

std::optional<Bytes> chacha20_poly1305_decrypt(
    const uint8_t* ciphertext_and_tag, std::size_t ciphertext_and_tag_len,
    const uint8_t* aad, std::size_t aad_len,
    const std::array<uint8_t, AEAD_NONCE_SIZE>& nonce,
    const std::array<uint8_t, AEAD_KEY_SIZE>& key) {
    ensure_sodium_initialized();
    if (ciphertext_and_tag_len < crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return std::nullopt;
    }

    Bytes plaintext(ciphertext_and_tag_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plen = 0;

    int res = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext.data(), &plen,
        nullptr,
        ciphertext_and_tag, ciphertext_and_tag_len,
        aad, aad_len,
        nonce.data(),
        key.data()
    );

    if (res != 0) {
        return std::nullopt; // Authentication failed (corrupted or tampered)
    }

    plaintext.resize(plen);
    return plaintext;
}

} // namespace p2p::security

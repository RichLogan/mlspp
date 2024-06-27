#include <hpke/openssl/openssl_provider.h>
#include <hpke/provider.h>

namespace MLS_NAMESPACE::hpke::openssl {

const Digest&
digest_from_suite(const Provider::ID suite)
{
  switch (suite) {
    // SHA256.
    case Provider::ID::X25519_AES128GCM_SHA256_Ed25519:
    case Provider::ID::P256_AES128GCM_SHA256_P256:
    case Provider::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519:
      return Digest::get<Digest::ID::SHA256>();
    // SHA512.
    case Provider::ID::P521_AES256GCM_SHA512_P521:
    case Provider::ID::X448_AES256GCM_SHA512_Ed448:
    case Provider::ID::X448_CHACHA20POLY1305_SHA512_Ed448:
      return Digest::get<Digest::ID::SHA512>();
    // SHA384.
    case Provider::ID::P384_AES256GCM_SHA384_P384:
      return Digest::get<Digest::ID::SHA384>();
    default:
      throw std::invalid_argument("Unsupported suite");
  }
}

const Signature&
sig_from_suite(const Provider::ID suite)
{
  switch (suite) {
    case Provider::ID::X25519_AES128GCM_SHA256_Ed25519:
    case Provider::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519:
      return Signature::get<Signature::ID::Ed25519>();
    case Provider::ID::P256_AES128GCM_SHA256_P256:
      return Signature::get<Signature::ID::P256_SHA256>();
    case Provider::ID::P521_AES256GCM_SHA512_P521:
      return Signature::get<Signature::ID::P521_SHA512>();
    case Provider::ID::X448_AES256GCM_SHA512_Ed448:
    case Provider::ID::X448_CHACHA20POLY1305_SHA512_Ed448:
      return Signature::get<Signature::ID::Ed448>();
    case Provider::ID::P384_AES256GCM_SHA384_P384:
      return Signature::get<Signature::ID::P384_SHA384>();
    default:
      throw std::invalid_argument("Unsupported suite");
  }
}

const HPKE hpke_from_suite(const Provider::ID id) {
    switch (id) {
        case Provider::ID::X25519_AES128GCM_SHA256_Ed25519:
            return HPKE(KEM::ID::DHKEM_X25519_SHA256,
                        KDF::ID::HKDF_SHA256,
                        AEAD::ID::AES_128_GCM);
        case Provider::ID::P256_AES128GCM_SHA256_P256:
            return HPKE(KEM::ID::DHKEM_P256_SHA256,
                        KDF::ID::HKDF_SHA256,
                        AEAD::ID::AES_128_GCM);
        case Provider::ID::X25519_CHACHA20POLY1305_SHA256_Ed25519:
            return HPKE(KEM::ID::DHKEM_X25519_SHA256,
                        KDF::ID::HKDF_SHA256,
                        AEAD::ID::CHACHA20_POLY1305);
        case Provider::ID::P521_AES256GCM_SHA512_P521:
            return HPKE(KEM::ID::DHKEM_P521_SHA512,
                        KDF::ID::HKDF_SHA512,
                        AEAD::ID::AES_256_GCM);
        case Provider::ID::P384_AES256GCM_SHA384_P384:
            return HPKE(KEM::ID::DHKEM_P384_SHA384,
                        KDF::ID::HKDF_SHA384,
                        AEAD::ID::AES_256_GCM);
        case Provider::ID::X448_AES256GCM_SHA512_Ed448:
            return HPKE(KEM::ID::DHKEM_X448_SHA512,
                        KDF::ID::HKDF_SHA512,
                        AEAD::ID::AES_256_GCM);
        case Provider::ID::X448_CHACHA20POLY1305_SHA512_Ed448:
            return HPKE(KEM::ID::DHKEM_X448_SHA512,
                        KDF::ID::HKDF_SHA512,
                        AEAD::ID::CHACHA20_POLY1305);
        default:
            throw std::invalid_argument("Unsupported suite");
    }
}

OpenSSLProvider::OpenSSLProvider(Provider::ID id_in)
  : _hpke(hpke_from_suite(id_in))
  , _digest(digest_from_suite(id_in))
  , _sig(sig_from_suite(id_in))
{
}

} // namespace MLS_NAMESPACE::hpke::openssl
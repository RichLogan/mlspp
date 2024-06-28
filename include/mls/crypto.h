#pragma once

#include <hpke/digest.h>
#include <hpke/hpke.h>
#include <hpke/random.h>
#include <hpke/signature.h>
#include <mls/common.h>
#include <namespace.h>
#include <tls/tls_syntax.h>
#include <vector>
#include <hpke/provider.h>

namespace MLS_NAMESPACE {

/// Signature Code points, borrowed from RFC 8446
enum struct SignatureScheme : uint16_t
{
  ecdsa_secp256r1_sha256 = 0x0403,
  ecdsa_secp384r1_sha384 = 0x0805,
  ecdsa_secp521r1_sha512 = 0x0603,
  ed25519 = 0x0807,
  ed448 = 0x0808,
  rsa_pkcs1_sha256 = 0x0401,
};

SignatureScheme
tls_signature_scheme(hpke::Signature::ID id);

/// Cipher suites

struct KeyAndNonce
{
  bytes key;
  bytes nonce;
};

// opaque HashReference<V>;
// HashReference KeyPackageRef;
// HashReference ProposalRef;
using HashReference = bytes;
using KeyPackageRef = HashReference;
using ProposalRef = HashReference;

struct CipherSuite
{
  using ID = hpke::Provider::ID;
  CipherSuite();
  CipherSuite(ID id_in, std::shared_ptr<hpke::Provider> provider = nullptr);

  void set_provider_from(const CipherSuite& suite);
  std::optional<std::shared_ptr<hpke::Provider>> get_provider() const { return provider; }
  ID cipher_suite() const { return id; }
  SignatureScheme signature_scheme() const;

  size_t secret_size() const { return provider.value()->digest().hash_size; }
  size_t key_size() const { return provider.value()->hpke().aead.key_size; }
  size_t nonce_size() const { return provider.value()->hpke().aead.nonce_size; }

  bytes zero() const { return bytes(secret_size(), 0); }
  const hpke::HPKE& hpke() const { return provider.value()->hpke(); }
  const hpke::Digest& digest() const { return provider.value()->digest(); }
  const hpke::Signature& sig() const { return provider.value()->sig(); }

  bytes expand_with_label(const bytes& secret,
                          const std::string& label,
                          const bytes& context,
                          size_t length) const;
  bytes derive_secret(const bytes& secret, const std::string& label) const;
  bytes derive_tree_secret(const bytes& secret,
                           const std::string& label,
                           uint32_t generation,
                           size_t length) const;

  template<typename T>
  bytes ref(const T& value) const
  {
    return raw_ref(reference_label<T>(), tls::marshal(value));
  }

  bytes raw_ref(const bytes& label, const bytes& value) const
  {
    // RefHash(label, value) = Hash(RefHashInput)
    //
    // struct {
    //   opaque label<V>;
    //   opaque value<V>;
    // } RefHashInput;
    auto w = tls::ostream();
    w << label << value;
    return digest().hash(w.bytes());
  }

  TLS_SERIALIZABLE(id)

private:
  ID id;
  std::optional<std::shared_ptr<hpke::Provider>> provider;

  template<typename T>
  static const bytes& reference_label();
};

#if WITH_BORINGSSL
extern const std::array<CipherSuite::ID, 5> all_supported_suites;
#else
extern const std::array<CipherSuite::ID, 7> all_supported_suites;
#endif

// Utilities
using MLS_NAMESPACE::hpke::random_bytes;

// HPKE Keys
namespace encrypt_label {
extern const std::string update_path_node;
extern const std::string welcome;
} // namespace encrypt_label

struct HPKECiphertext
{
  bytes kem_output;
  bytes ciphertext;

  TLS_SERIALIZABLE(kem_output, ciphertext)
};

struct HPKEPublicKey
{
  bytes data;

  HPKECiphertext encrypt(CipherSuite suite,
                         const std::string& label,
                         const bytes& context,
                         const bytes& pt) const;

  std::tuple<bytes, bytes> do_export(CipherSuite suite,
                                     const bytes& info,
                                     const std::string& label,
                                     size_t size) const;

  TLS_SERIALIZABLE(data)
};

struct HPKEPrivateKey
{
  static HPKEPrivateKey generate(CipherSuite suite);
  static HPKEPrivateKey parse(CipherSuite suite, const bytes& data);
  static HPKEPrivateKey derive(CipherSuite suite, const bytes& secret);

  HPKEPrivateKey() = default;

  bytes data;
  HPKEPublicKey public_key;

  bytes decrypt(CipherSuite suite,
                const std::string& label,
                const bytes& context,
                const HPKECiphertext& ct) const;

  bytes do_export(CipherSuite suite,
                  const bytes& info,
                  const bytes& kem_output,
                  const std::string& label,
                  size_t size) const;

  void set_public_key(CipherSuite suite);

  TLS_SERIALIZABLE(data)

private:
  HPKEPrivateKey(bytes priv_data, bytes pub_data);
};

// Signature Keys
namespace sign_label {
extern const std::string mls_content;
extern const std::string leaf_node;
extern const std::string key_package;
extern const std::string group_info;
extern const std::string multi_credential;
} // namespace sign_label

struct SignaturePublicKey
{
  static SignaturePublicKey from_jwk(CipherSuite suite,
                                     const std::string& json_str);

  bytes data;

  bool verify(const CipherSuite& suite,
              const std::string& label,
              const bytes& message,
              const bytes& signature) const;

  std::string to_jwk(CipherSuite suite) const;

  TLS_SERIALIZABLE(data)
};

struct PublicJWK
{
  SignatureScheme signature_scheme;
  std::optional<std::string> key_id;
  SignaturePublicKey public_key;

  static PublicJWK parse(const std::string& jwk_json);
};

struct SignaturePrivateKey
{
  static SignaturePrivateKey generate(CipherSuite suite);
  static SignaturePrivateKey parse(CipherSuite suite, const bytes& data);
  static SignaturePrivateKey derive(CipherSuite suite, const bytes& secret);
  static SignaturePrivateKey from_jwk(CipherSuite suite,
                                      const std::string& json_str);

  SignaturePrivateKey() = default;

  bytes data;
  SignaturePublicKey public_key;

  bytes sign(const CipherSuite& suite,
             const std::string& label,
             const bytes& message) const;

  void set_public_key(CipherSuite suite);
  std::string to_jwk(CipherSuite suite) const;

  TLS_SERIALIZABLE(data)

private:
  SignaturePrivateKey(bytes priv_data, bytes pub_data);
};

} // namespace MLS_NAMESPACE

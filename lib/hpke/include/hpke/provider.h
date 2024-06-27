#pragma once

#include <hpke/digest.h>
#include <hpke/hpke.h>
#include <hpke/signature.h>
#include <namespace.h>

namespace MLS_NAMESPACE::hpke {

class Provider
{
public:
  enum struct ID : uint16_t
  {
    unknown = 0x0000,
    X25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    P256_AES128GCM_SHA256_P256 = 0x0002,
    X25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    X448_AES256GCM_SHA512_Ed448 = 0x0004,
    P521_AES256GCM_SHA512_P521 = 0x0005,
    X448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    P384_AES256GCM_SHA384_P384 = 0x0007,

    // GREASE values, included here mainly so that debugger output looks nice
    GREASE_0 = 0x0A0A,
    GREASE_1 = 0x1A1A,
    GREASE_2 = 0x2A2A,
    GREASE_3 = 0x3A3A,
    GREASE_4 = 0x4A4A,
    GREASE_5 = 0x5A5A,
    GREASE_6 = 0x6A6A,
    GREASE_7 = 0x7A7A,
    GREASE_8 = 0x8A8A,
    GREASE_9 = 0x9A9A,
    GREASE_A = 0xAAAA,
    GREASE_B = 0xBABA,
    GREASE_C = 0xCACA,
    GREASE_D = 0xDADA,
    GREASE_E = 0xEAEA,
  };

  virtual const hpke::HPKE& hpke() const = 0;
  virtual const hpke::Digest& digest() const = 0;
  virtual const hpke::Signature& sig() const = 0;
  virtual ~Provider() = default;
};

} // namespace MLS_NAMESPACE
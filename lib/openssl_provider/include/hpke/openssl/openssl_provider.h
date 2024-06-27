#include <hpke/provider.h>

namespace MLS_NAMESPACE::hpke::openssl {
class OpenSSLProvider : public Provider
{
public:
  OpenSSLProvider(Provider::ID id_in);
  virtual const hpke::HPKE& hpke() const override { return _hpke; }
  virtual const hpke::Digest& digest() const override { return _digest; }
  virtual const hpke::Signature& sig() const override { return _sig; }

private:
  const hpke::HPKE _hpke;
  const hpke::Digest& _digest;
  const hpke::Signature& _sig;
};
} // namespace MLS_NAMESPACE::openssl
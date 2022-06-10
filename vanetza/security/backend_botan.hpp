#ifndef BACKEND_BOTAN_HPP_3E6GMTPL
#define BACKEND_BOTAN_HPP_3E6GMTPL

#include <vanetza/security/backend.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A backend based on the Botan crypto library
 *
 *
 */
class BackendBotan : public Backend
{
public:
    static constexpr auto backend_name = "Botan";

    /// \see Backend::sign_data
    EcdsaSignature sign_data(const ecdsa256::PrivateKey& private_key, const ByteBuffer& data_buffer) override;

    /// \see Backend::verify_data
    bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const EcdsaSignature& sig) override;

    /// \see Backend::decompress_point
    boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point) override;

private:
    EcdsaSignature fake_signature() const;
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_BOTAN_HPP_3E6GMTPL */


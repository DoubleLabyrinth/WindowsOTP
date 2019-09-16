#pragma once
#include "OtpType.hpp"
#include "Internal/OtpExceptionCategory.hpp"
#include "Internal/OtpResource.hpp"
#include "Internal/OtpResourceTraitsCng.hpp"
#include "Internal/OtpCng.hpp"
#include "OtpByteArray.hpp"
#include "OtpBase32.hpp"
#include "OtpBase64.hpp"
#include "OtpSerialization.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>

#pragma comment(lib, "bcrypt")

namespace WinOTP {

    enum class OtpHashMode {
        Sha1,
        Sha256,
        Sha384,
        Sha512
    };

    class OtpGeneratorRfc4226 {
    protected:

        const OtpHashMode   m_HashMode;
        const OtpTypeUInt32 m_Digit;
        OtpByteArraySecure  m_RawSecret;
        OtpByteArraySecure  m_HashObject;
        Internal::OtpResource<Internal::OtpResourceTraitsCngHashHandle> m_HashHandle;

        [[nodiscard]]
        static constexpr Internal::OtpCngHashEnum ConvertToCngHashEnum(OtpHashMode HashMode) {
            switch (HashMode) {
                case OtpHashMode::Sha1:
                    return Internal::OtpCngHashEnum::Sha1;
                case OtpHashMode::Sha256:
                    return Internal::OtpCngHashEnum::Sha256;
                case OtpHashMode::Sha384:
                    return Internal::OtpCngHashEnum::Sha384;
                case OtpHashMode::Sha512:
                    return Internal::OtpCngHashEnum::Sha512;
                default:
                    __assume(0);
            }
        }

        [[nodiscard]]
        static constexpr OtpTypeUInt32 DigitRangeSpace(OtpTypeUInt32 Digit) noexcept {
            OtpTypeUInt32 Result = 1;

            for (OtpTypeUInt32 i = 0; i < Digit; ++i) {
                Result *= 10;
            }

            return Result;
        }

        OtpGeneratorRfc4226& ImportSecretRaw(OtpByteArraySecure& RawSecret) {
            if (RawSecret.size() > ULONG_MAX) {
                throw std::length_error("Secret is too long.");
            } else {
                using namespace Internal;

                const auto& HashProvider = OtpCngCategoryHmac(ConvertToCngHashEnum(m_HashMode));
                OtpByteArraySecure HashObject(HashProvider.GetHashObjectSize());
                OtpResource<OtpResourceTraitsCngHashHandle> HashHandle;

                auto ntStatus = BCryptCreateHash(
                    HashProvider.GetNativeHandle(),
                    HashHandle.GetAddressOf(),
                    HashObject.data(),
                    static_cast<ULONG>(HashObject.size()),
                    RawSecret.data(),
                    static_cast<ULONG>(RawSecret.size()),
                    BCRYPT_HASH_REUSABLE_FLAG
                );
                if (!BCRYPT_SUCCESS(ntStatus)) {
                    throw std::system_error(
                        ntStatus,
                        OtpExceptionWinNTCategory()
                    );
                }

                m_RawSecret.swap(RawSecret);
                m_HashObject.swap(HashObject);
                std::swap(m_HashHandle, HashHandle);

                auto p = m_HashObject.data();
                auto pp = m_HashHandle.Get();

                return *this;
            }
        }

    public:

        OtpGeneratorRfc4226(OtpHashMode HashMode = OtpHashMode::Sha1, OtpTypeUInt32 Digit = 6) :
            m_HashMode(HashMode),
            m_Digit(Digit) 
        {
            if ((6 <= Digit && Digit <= 8) == false) {
                throw std::invalid_argument("Digit is required to be between 6 to 8.");
            }
        }

        [[nodiscard]]
        OtpHashMode GetHashMode() const noexcept {
            return m_HashMode;
        }

        [[nodiscard]]
        OtpTypeUInt32 GetDigit() const noexcept {
            return m_Digit;
        }

        [[nodiscard]]
        std::vector<OtpTypeByte> ExportSecretRaw() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return m_RawSecret;
            }
        }

        [[nodiscard]]
        std::string ExportSecretBase32A() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return OtpBase32EncodeA(m_RawSecret);
            }
        }

        [[nodiscard]]
        std::wstring ExportSecretBase32W() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return OtpBase32EncodeW(m_RawSecret);
            }
        }

        [[nodiscard]]
        std::string ExportSecretBase64A() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return OtpBase64EncodeA(m_RawSecret);
            }
        }

        [[nodiscard]]
        std::wstring ExportSecretBase64W() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return OtpBase64EncodeW(m_RawSecret);
            }
        }

        OtpGeneratorRfc4226& ImportSecretRaw(const void* lpRawSecret, size_t cbRawSecret) {
            if (cbRawSecret > ULONG_MAX) {
                throw std::length_error("Secret is too long.");
            } else {
                OtpByteArraySecure RawSecret(
                    reinterpret_cast<const OtpTypeByte*>(lpRawSecret),
                    reinterpret_cast<const OtpTypeByte*>(lpRawSecret) + cbRawSecret
                );

                return ImportSecretRaw(RawSecret);
            }
        }

        OtpGeneratorRfc4226& ImportSecretBase32A(std::string_view Base32Secret) {
            OtpByteArraySecure RawSecret = OtpBase32DecodeA(Base32Secret);
            return ImportSecretRaw(RawSecret);
        }

        OtpGeneratorRfc4226& ImportSecretBase32W(std::wstring_view Base32Secret) {
            OtpByteArraySecure RawSecret = OtpBase32DecodeW(Base32Secret);
            return ImportSecretRaw(RawSecret);
        }

        OtpGeneratorRfc4226& ImportSecretBase64A(std::string_view Base64Secret) {
            OtpByteArraySecure RawSecret = OtpBase64DecodeA(Base64Secret);
            return ImportSecretRaw(RawSecret);
        }

        OtpGeneratorRfc4226& ImportSecretBase64W(std::wstring_view Base64Secret) {
            OtpByteArraySecure RawSecret = OtpBase64DecodeW(Base64Secret);
            return ImportSecretRaw(RawSecret);
        }

        [[nodiscard]]
        OtpTypeUInt32 GenerateCode(OtpTypeUInt64 Counter) const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret is not given.");
            } else {
                using namespace Internal;

                OtpByteArray HmacHash(OtpCngCategoryHmac(ConvertToCngHashEnum(m_HashMode)).GetHashSize());
                alignas(OtpTypeUInt64) UCHAR CounterBytes[sizeof(OtpTypeUInt64)];

                OtpSerializationIntegerToBytes<OtpSerializationEndian::Big>(Counter, CounterBytes);

                auto ntStatus = BCryptHashData(m_HashHandle.Get(), CounterBytes, sizeof(CounterBytes), 0);
                if (!BCRYPT_SUCCESS(ntStatus)) {
                    throw std::system_error(
                        ntStatus,
                        OtpExceptionWinNTCategory()
                    );
                }

                ntStatus = BCryptFinishHash(m_HashHandle.Get(), HmacHash.data(), static_cast<ULONG>(HmacHash.size()), 0);
                if (!BCRYPT_SUCCESS(ntStatus)) {
                    throw std::system_error(
                        ntStatus,
                        OtpExceptionWinNTCategory()
                    );
                }

                OtpTypeByte Offset = HmacHash.back() & 0xF;
                OtpTypeUInt32 Code = OtpSerializationBytesToInteger<OtpSerializationEndian::Big, OtpTypeUInt32>(HmacHash.data() + Offset);
                
                Code &= static_cast<OtpTypeUInt32>(0x7FFFFFFF);
                Code %= DigitRangeSpace(m_Digit);

                return Code;
            }
        }

        [[nodiscard]]
        std::string GenerateCodeStringA(OtpTypeUInt64 Counter) const {
            auto Code = GenerateCode(Counter);
            auto CodeString = std::to_string(Code);

            if (CodeString.length() < m_Digit) {
                CodeString.insert(CodeString.begin(), m_Digit - CodeString.length(), '0');
            }

            return CodeString;
        }

        [[nodiscard]]
        std::wstring GenerateCodeStringW(OtpTypeUInt64 Counter) const {
            auto Code = GenerateCode(Counter);
            auto CodeString = std::to_wstring(Code);

            if (CodeString.length() < m_Digit) {
                CodeString.insert(CodeString.begin(), m_Digit - CodeString.length(), L'0');
            }

            return CodeString;
        }

#if defined(_UNICODE) || defined(UNICODE)
        [[nodiscard]]
        std::wstring ExportSecretBase32() const {
            return ExportSecretBase32W();
        }

        OtpGeneratorRfc4226& ImportSecretBase32(std::wstring_view Base32Secret) {
            return ImportSecretBase32W(Base32Secret);
        }

        OtpGeneratorRfc4226& ImportSecretBase64(std::wstring_view Base64Secret) {
            return ImportSecretBase64W(Base64Secret);
        }

        [[nodiscard]]
        std::wstring GenerateCodeString(OtpTypeUInt64 Counter) const {
            return GenerateCodeStringW(Counter);
        }
#else
        [[nodiscard]]
        std::string ExportSecretBase32() const {
            return ExportSecretBase32A();
        }

        OtpGeneratorRfc4226& ImportSecretBase32(std::string_view Base32Secret) {
            return ImportSecretBase32A(Base32Secret);
        }

        OtpGeneratorRfc4226& ImportSecretBase64(std::string_view Base64Secret) {
            return ImportSecretBase64A(Base64Secret);
        }

        [[nodiscard]]
        std::string GenerateCodeString(OtpTypeUInt64 Counter) const {
            return GenerateCodeStringA(Counter);
        }
#endif

    };

}


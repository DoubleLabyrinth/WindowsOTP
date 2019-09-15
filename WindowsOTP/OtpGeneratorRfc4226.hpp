#pragma once
#include "OtpType.hpp"
#include "OtpUtilsBase32.hpp"
#include "OtpUtilsBase64.hpp"
#include "OtpUtilsNtExceptionCategory.hpp"
#include "OtpUtilsSerialization.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>

#pragma comment(lib, "bcrypt")

namespace WinOTP {

    class OtpGeneratorRfc4226 {
    protected:

        const OtpHashMode m_HashMode;
        const OtpTypeUInt32   m_Digit;
        std::vector<OtpTypeByte> m_RawSecret;

        [[nodiscard]]
        static BCRYPT_ALG_HANDLE CngHmacAlgorithmCategory(OtpHashMode HashMode) {
            switch (HashMode) {
                case OtpHashMode::Sha1:
                    return BCRYPT_HMAC_SHA1_ALG_HANDLE;
                case OtpHashMode::Sha256:
                    return BCRYPT_HMAC_SHA256_ALG_HANDLE;
                case OtpHashMode::Sha512:
                    return BCRYPT_HMAC_SHA512_ALG_HANDLE;
                default:
                    throw std::invalid_argument("Unknown hash mode detected.");
            }
        }

        [[nodiscard]]
        static OtpTypeSize CngHmacHashSize(BCRYPT_ALG_HANDLE hAlgorithm) {
            NTSTATUS ntStatus = 0;
            ULONG cbReturnData;
            DWORD cbHash = 0;

            ntStatus = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&cbHash), sizeof(DWORD), &cbReturnData, 0);
            if (!BCRYPT_SUCCESS(ntStatus)) {
                throw std::system_error(
                    ntStatus, 
                    Utils::OtpExceptionWinNTCategory()
                );
            }

            return cbHash;
        }

        [[nodiscard]]
        static constexpr OtpTypeUInt32 DigitSpace(OtpTypeUInt32 Digit) noexcept {
            OtpTypeUInt32 Result = 1;

            for (OtpTypeUInt32 i = 0; i < Digit; ++i) {
                Result *= 10;
            }

            return Result;
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
                return Utils::OtpBase32EncodeA(m_RawSecret);
            }
        }

        [[nodiscard]]
        std::wstring ExportSecretBase32W() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return Utils::OtpBase32EncodeW(m_RawSecret);
            }
        }

        [[nodiscard]]
        std::string ExportSecretBase64A() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return Utils::OtpBase64EncodeA(m_RawSecret);
            }
        }

        [[nodiscard]]
        std::wstring ExportSecretBase64W() const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret has not been set.");
            } else {
                return Utils::OtpBase64EncodeW(m_RawSecret);
            }
        }

        OtpGeneratorRfc4226& ImportSecretRaw(const void* lpRawSecret, size_t cbRawSecret) {
            if (cbRawSecret > ULONG_MAX) {
                throw std::length_error("Secret is too long.");
            } else {
                std::vector<OtpTypeByte> RawSecret(
                    reinterpret_cast<const OtpTypeByte*>(lpRawSecret),
                    reinterpret_cast<const OtpTypeByte*>(lpRawSecret) + cbRawSecret
                );

                std::swap(m_RawSecret, RawSecret);
                SecureZeroMemory(RawSecret.data(), RawSecret.size());
                return *this;
            }
        }

        OtpGeneratorRfc4226& ImportSecretBase32A(std::string_view Base32Secret) {
            auto RawSecret = Utils::OtpBase32DecodeA(Base32Secret);

            if (RawSecret.size() > ULONG_MAX) {
                throw std::length_error("Secret is too long.");
            } else {
                std::swap(m_RawSecret, RawSecret);
                SecureZeroMemory(RawSecret.data(), RawSecret.size());
                return *this;
            }
        }

        OtpGeneratorRfc4226& ImportSecretBase32W(std::wstring_view Base32Secret) {
            auto RawSecret = Utils::OtpBase32DecodeW(Base32Secret);

            if (RawSecret.size() > ULONG_MAX) {
                throw std::length_error("Secret is too long.");
            } else {
                std::swap(m_RawSecret, RawSecret);
                SecureZeroMemory(RawSecret.data(), RawSecret.size());
                return *this;
            }
        }

        OtpGeneratorRfc4226& ImportSecretBase64A(std::string_view Base64Secret) {
            auto RawSecret = Utils::OtpBase64DecodeA(Base64Secret);

            if (RawSecret.size() > ULONG_MAX) {
                throw std::length_error("Secret is too long.");
            } else {
                std::swap(m_RawSecret, RawSecret);
                SecureZeroMemory(RawSecret.data(), RawSecret.size());
                return *this;
            }
        }

        OtpGeneratorRfc4226& ImportSecretBase64W(std::wstring_view Base64Secret) {
            auto RawSecret = Utils::OtpBase64DecodeW(Base64Secret);

            if (RawSecret.size() > ULONG_MAX) {
                throw std::length_error("Secret is too long.");
            } else {
                std::swap(m_RawSecret, RawSecret);
                SecureZeroMemory(RawSecret.data(), RawSecret.size());
                return *this;
            }
        }

        [[nodiscard]]
        OtpTypeUInt32 GenerateCode(OtpTypeUInt64 Counter) const {
            if (m_RawSecret.size() == 0) {
                throw std::runtime_error("Secret is not given.");
            } else {
                NTSTATUS ntStatus = 0;
                BCRYPT_ALG_HANDLE hAlgorithm = CngHmacAlgorithmCategory(m_HashMode);
                std::vector<OtpTypeByte> HmacHash(CngHmacHashSize(hAlgorithm));
                alignas(OtpTypeUInt64) UCHAR CounterBytes[sizeof(OtpTypeUInt64)];

                Utils::OtpIntegerToBytes<OtpEnumEndian::Big>(Counter, CounterBytes);

                ntStatus = BCryptHash(
                    hAlgorithm, 
                    const_cast<PUCHAR>(m_RawSecret.data()), static_cast<DWORD>(m_RawSecret.size()), 
                    CounterBytes, sizeof(CounterBytes), 
                    HmacHash.data(), static_cast<DWORD>(HmacHash.size())
                );
                if (!BCRYPT_SUCCESS(ntStatus)) {
                    throw std::system_error(
                        ntStatus,
                        Utils::OtpExceptionWinNTCategory()
                    );
                }

                OtpTypeByte Offset = HmacHash.back() & 0xF;
                OtpTypeUInt32 Code = Utils::OtpBytesToInteger<OtpEnumEndian::Big, OtpTypeUInt32>(HmacHash.data() + Offset);
                
                Code &= static_cast<OtpTypeUInt32>(0x7FFFFFFF);
                Code %= DigitSpace(m_Digit);

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

        ~OtpGeneratorRfc4226() {
            SecureZeroMemory(m_RawSecret.data(), m_RawSecret.size());
        }

    };

}


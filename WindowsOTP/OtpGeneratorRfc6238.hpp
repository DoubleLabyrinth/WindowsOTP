#pragma once
#include "OtpGeneratorRfc4226.hpp"
#include <time.h>

namespace WinOTP {

    class OtpGeneratorRfc6238 : public OtpGeneratorRfc4226 {
    protected:

        const OtpTypeUInt32 m_Interval;
        
        using OtpGeneratorRfc4226::ImportSecretRaw;
        using OtpGeneratorRfc4226::ImportSecretBase32;
        using OtpGeneratorRfc4226::ImportSecretBase32A;
        using OtpGeneratorRfc4226::ImportSecretBase32W;
        using OtpGeneratorRfc4226::ImportSecretBase64;
        using OtpGeneratorRfc4226::ImportSecretBase64A;
        using OtpGeneratorRfc4226::ImportSecretBase64W;
        using OtpGeneratorRfc4226::GenerateCode;
        using OtpGeneratorRfc4226::GenerateCodeString;
        using OtpGeneratorRfc4226::GenerateCodeStringA;
        using OtpGeneratorRfc4226::GenerateCodeStringW;

    public:

        OtpGeneratorRfc6238(OtpHashMode HashMode = OtpHashMode::Sha1, OtpTypeUInt32 Digit = 6, OtpTypeUInt32 Interval = 30) :
            OtpGeneratorRfc4226(HashMode, Digit),
            m_Interval(Interval) 
        {
            if (m_Interval == 0) {
                throw std::invalid_argument("Interval cannot be zero.");
            }
        }

        OtpGeneratorRfc6238& ImportSecretRaw(const void* lpRawSecret, size_t cbRawSecret) {
            OtpGeneratorRfc4226::ImportSecretRaw(lpRawSecret, cbRawSecret);
            return *this;
        }

        OtpGeneratorRfc6238& ImportSecretBase32A(std::string_view Base32Secret) {
            OtpGeneratorRfc4226::ImportSecretBase32A(Base32Secret);
            return *this;
        }

        OtpGeneratorRfc6238& ImportSecretBase32W(std::wstring_view Base32Secret) {
            OtpGeneratorRfc4226::ImportSecretBase32W(Base32Secret);
            return *this;
        }

        OtpGeneratorRfc6238& ImportSecretBase64A(std::string_view Base64Secret) {
            OtpGeneratorRfc4226::ImportSecretBase64A(Base64Secret);
            return *this;
        }

        OtpGeneratorRfc6238& ImportSecretBase64W(std::wstring_view Base64Secret) {
            OtpGeneratorRfc4226::ImportSecretBase64W(Base64Secret);
            return *this;
        }

        OtpTypeUInt32 GenerateCode(OtpTypeUInt64 UnixTimestamp, OtpTypeUInt64 UnixTimestampStartCounting = 0) {
            auto T = (UnixTimestamp - UnixTimestampStartCounting) / m_Interval;
            return OtpGeneratorRfc4226::GenerateCode(T);
        }

        OtpTypeUInt32 GenerateCode() {
            return GenerateCode(_time64(nullptr), 0);
        }

        std::string GenerateCodeStringA(OtpTypeUInt64 UnixTimestamp, OtpTypeUInt64 UnixTimestampStartCounting = 0) {
            auto Code = GenerateCode(UnixTimestamp, UnixTimestampStartCounting);
            auto CodeString = std::to_string(Code);

            if (CodeString.length() < m_Digit) {
                CodeString.insert(CodeString.begin(), m_Digit - CodeString.length(), '0');
            }

            return CodeString;
        }

        std::string GenerateCodeStringA() {
            auto Code = GenerateCode();
            auto CodeString = std::to_string(Code);

            if (CodeString.length() < m_Digit) {
                CodeString.insert(CodeString.begin(), m_Digit - CodeString.length(), '0');
            }

            return CodeString;
        }

        std::wstring GenerateCodeStringW(OtpTypeUInt64 UnixTimestamp, OtpTypeUInt64 UnixTimestampStartCounting = 0) {
            auto Code = GenerateCode(UnixTimestamp, UnixTimestampStartCounting);
            auto CodeString = std::to_wstring(Code);

            if (CodeString.length() < m_Digit) {
                CodeString.insert(CodeString.begin(), m_Digit - CodeString.length(), L'0');
            }

            return CodeString;
        }

        std::wstring GenerateCodeStringW() {
            auto Code = GenerateCode();
            auto CodeString = std::to_wstring(Code);

            if (CodeString.length() < m_Digit) {
                CodeString.insert(CodeString.begin(), m_Digit - CodeString.length(), L'0');
            }

            return CodeString;
        }

#if defined(_UNICODE) || defined(UNICODE)
        OtpGeneratorRfc6238& ImportSecretBase32(std::wstring_view Base32Secret) {
            OtpGeneratorRfc4226::ImportSecretBase32(Base32Secret);
            return *this;
        }

        OtpGeneratorRfc6238& ImportSecretBase64(std::wstring_view Base32Secret) {
            OtpGeneratorRfc4226::ImportSecretBase64(Base32Secret);
            return *this;
        }

        std::wstring GenerateCodeString(OtpTypeUInt64 UnixTimestamp, OtpTypeUInt64 UnixTimestampStartCounting = 0) {
            return GenerateCodeStringW(UnixTimestamp, UnixTimestampStartCounting);
        }

        std::wstring GenerateCodeString() {
            return GenerateCodeStringW();
        }
#else
        OtpGeneratorRfc6238& ImportSecretBase32(std::string_view Base32Secret) {
            OtpGeneratorRfc4226::ImportSecretBase32(Base32Secret);
            return *this;
        }

        OtpGeneratorRfc6238& ImportSecretBase64(std::string_view Base32Secret) {
            OtpGeneratorRfc4226::ImportSecretBase64(Base32Secret);
            return *this;
        }

        std::string GenerateCodeString(OtpTypeUInt64 UnixTimestamp, OtpTypeUInt64 UnixTimestampStartCounting = 0) {
            return GenerateCodeStringA(UnixTimestamp, UnixTimestampStartCounting);
        }

        std::string GenerateCodeString() {
            return GenerateCodeStringA();
        }
#endif

    };

}


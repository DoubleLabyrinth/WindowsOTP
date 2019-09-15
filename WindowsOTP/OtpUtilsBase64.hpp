#pragma once
#include <stdexcept>
#include <string>
#include <vector>
#include "OtpType.hpp"

namespace WinOTP::Utils {

    [[nodiscard]]
    inline std::string OtpBase64EncodeA(const std::vector<OtpTypeByte>& Bytes) {
        static const std::string::value_type Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        static constexpr std::string::value_type PaddingChar = '=';

        std::string szBase64;

        if (Bytes.size()) {
            szBase64.reserve((Bytes.size() * 8 + 5) / 6);

            OtpTypeByte Idx = 0;
            OtpTypeByte BitsLeft = 8;
            for (size_t i = 0; i < Bytes.size();) {
                if (BitsLeft < 6) {
                    Idx = Bytes[i] << (6 - BitsLeft);

                    ++i;
                    if (i != Bytes.size()) {
                        Idx |= Bytes[i] >> (2 + BitsLeft);
                    }

                    Idx &= 0x3F;
                    BitsLeft += 2;
                } else {
                    Idx = Bytes[i] >> (BitsLeft - 6);

                    Idx &= 0x3F;
                    BitsLeft -= 6;
                }

                szBase64.append(1, Alphabet[Idx]);

                if (BitsLeft == 0) {
                    BitsLeft = 8;
                    ++i;
                }
            }

            if (szBase64.length() % 4) {
                size_t Padding = 4 - szBase64.length() % 4;
                szBase64.append(Padding, PaddingChar);
            }
        }

        return szBase64;
    }

    [[nodiscard]]
    inline std::wstring OtpBase64EncodeW(const std::vector<OtpTypeByte>& Bytes) {
        static const std::wstring::value_type Alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        static constexpr std::wstring::value_type PaddingChar = L'=';

        std::wstring szBase64;

        if (Bytes.size()) {
            szBase64.reserve((Bytes.size() * 8 + 5) / 6);

            OtpTypeByte Idx = 0;
            OtpTypeByte BitsLeft = 8;
            for (size_t i = 0; i < Bytes.size();) {
                if (BitsLeft < 6) {
                    Idx = Bytes[i] << (6 - BitsLeft);

                    ++i;
                    if (i != Bytes.size()) {
                        Idx |= Bytes[i] >> (2 + BitsLeft);
                    }

                    Idx &= 0x3F;
                    BitsLeft += 2;
                } else {
                    Idx = Bytes[i] >> (BitsLeft - 6);

                    Idx &= 0x3F;
                    BitsLeft -= 6;
                }

                szBase64.append(1, Alphabet[Idx]);

                if (BitsLeft == 0) {
                    BitsLeft = 8;
                    ++i;
                }
            }

            if (szBase64.length() % 4) {
                size_t Padding = 4 - szBase64.length() % 4;
                szBase64.append(Padding, PaddingChar);
            }
        }

        return szBase64;
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase64DecodeA(std::string_view szBase64) {
        static constexpr std::string::value_type PaddingChar = '=';

        std::vector<OtpTypeByte> Bytes;

        if (szBase64.length()) {
            Bytes.reserve((szBase64.length() * 6 + 7) / 8);

            OtpTypeByte Byte = 0;
            OtpTypeByte BitsNeed = 8;
            for (size_t i = 0; i < szBase64.length(); ++i) {
                OtpTypeByte Idx;
                if ('A' <= szBase64[i] && szBase64[i] <= 'Z') {
                    Idx = szBase64[i] - 'A';
                } else if ('a' <= szBase64[i] && szBase64[i] <= 'z') {
                    Idx = szBase64[i] - 'a' + 26;
                } else if ('0' <= szBase64[i] && szBase64[i] <= '9') {
                    Idx = szBase64[i] - '0' + 26 + 26;
                } else if (szBase64[i] == '+') {
                    Idx = 26 + 26 + 10;
                } else if (szBase64[i] == '/') {
                    Idx = 26 + 26 + 10 + 1;
                } else if (szBase64[i] == PaddingChar) {
                    for (size_t j = i + 1; j < szBase64.length(); ++j) {
                        if (szBase64[j] != PaddingChar) {
                            throw std::invalid_argument("Invalid padding schema detected.");
                        }
                    }

                    break;
                } else {
                    throw std::invalid_argument("Non-Base64 character detected.");
                }

                if (BitsNeed >= 6) {
                    Byte |= Idx;

                    BitsNeed -= 6;
                    Byte <<= BitsNeed;
                } else {
                    Byte |= Idx >> (6 - BitsNeed);
                    Bytes.push_back(Byte);

                    BitsNeed += 2;
                    Byte = Idx << BitsNeed;
                    if (BitsNeed > 6) {
                        Byte >>= BitsNeed - 6;
                    }
                }
            }

            if (BitsNeed < 6) {
                Bytes.push_back(Byte);
            }
        }

        return Bytes;
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase64DecodeW(std::wstring_view szBase64) {
        static constexpr std::wstring::value_type PaddingChar = L'=';

        std::vector<OtpTypeByte> Bytes;

        if (szBase64.length()) {
            Bytes.reserve((szBase64.length() * 6 + 7) / 8);

            OtpTypeByte Byte = 0;
            OtpTypeByte BitsNeed = 8;
            for (size_t i = 0; i < szBase64.length(); ++i) {
                OtpTypeByte Idx;
                if (L'A' <= szBase64[i] && szBase64[i] <= L'Z') {
                    Idx = szBase64[i] - L'A';
                } else if (L'a' <= szBase64[i] && szBase64[i] <= L'z') {
                    Idx = szBase64[i] - L'a' + 26;
                } else if (L'0' <= szBase64[i] && szBase64[i] <= L'9') {
                    Idx = szBase64[i] - L'0' + 26 + 26;
                } else if (szBase64[i] == L'+') {
                    Idx = 26 + 26 + 10;
                } else if (szBase64[i] == L'/') {
                    Idx = 26 + 26 + 10 + 1;
                } else if (szBase64[i] == PaddingChar) {
                    for (size_t j = i + 1; j < szBase64.length(); ++j) {
                        if (szBase64[j] != PaddingChar) {
                            throw std::invalid_argument("Invalid padding schema detected.");
                        }
                    }

                    break;
                } else {
                    throw std::invalid_argument("Non-Base64 character detected.");
                }

                if (BitsNeed >= 6) {
                    Byte |= Idx;

                    BitsNeed -= 6;
                    Byte <<= BitsNeed;
                } else {
                    Byte |= Idx >> (6 - BitsNeed);
                    Bytes.push_back(Byte);

                    BitsNeed += 2;
                    Byte = Idx << BitsNeed;
                    if (BitsNeed > 6) {
                        Byte >>= BitsNeed - 6;
                    }
                }
            }

            if (BitsNeed < 6) {
                Bytes.push_back(Byte);
            }
        }

        return Bytes;
    }

#if defined(_UNICODE) || defined(UNICODE)
    [[nodiscard]]
    inline std::wstring OtpBase64Encode(const std::vector<OtpTypeByte>& Bytes) {
        return OtpBase64EncodeW(Bytes);
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase64Decode(std::wstring_view szBase64) {
        return OtpBase64DecodeW(szBase64);
    }
#else
    [[nodiscard]]
    inline std::string OtpBase64Encode(const std::vector<OtpTypeByte>& Bytes) {
        return OtpBase64EncodeA(Bytes);
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase64Decode(std::string_view szBase64) {
        return OtpBase64DecodeA(szBase64);
    }
#endif
}


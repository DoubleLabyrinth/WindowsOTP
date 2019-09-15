#include <stdexcept>
#include <string>
#include <vector>
#include "OtpType.hpp"

namespace WinOTP::Utils {

    [[nodiscard]]
    inline std::string OtpBase32EncodeA(const std::vector<OtpTypeByte>& Bytes) {
        static const std::string::value_type Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        static constexpr std::string::value_type PaddingChar = '=';

        std::string szBase32;

        if (Bytes.size()) {
            szBase32.reserve((Bytes.size() * 8 + 4) / 5);

            OtpTypeByte Idx = 0;
            OtpTypeByte BitsLeft = 8;
            for (size_t i = 0; i < Bytes.size();) {
                if (BitsLeft < 5) {
                    Idx = Bytes[i] << (5 - BitsLeft);

                    ++i;
                    if (i != Bytes.size()) {
                        Idx |= Bytes[i] >> (3 + BitsLeft);
                    }

                    Idx &= 0x1F;
                    BitsLeft += 3;
                } else {
                    Idx = Bytes[i] >> (BitsLeft - 5);

                    Idx &= 0x1F;
                    BitsLeft -= 5;
                }

                szBase32.append(1, Alphabet[Idx]);

                if (BitsLeft == 0) {
                    BitsLeft = 8;
                    ++i;
                }
            }

            if (szBase32.length() % 8) {
                size_t Padding = 8 - szBase32.length() % 8;
                szBase32.append(Padding, PaddingChar);
            }
        }

        return szBase32;
    }

    [[nodiscard]]
    inline std::wstring OtpBase32EncodeW(const std::vector<OtpTypeByte>& Bytes) {
        static const std::wstring::value_type Alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        static constexpr std::wstring::value_type PaddingChar = L'=';

        std::wstring szBase32;

        if (Bytes.size()) {
            szBase32.reserve((Bytes.size() * 8 + 4) / 5);

            OtpTypeByte Idx = 0;
            OtpTypeByte BitsLeft = 8;
            for (size_t i = 0; i < Bytes.size();) {
                if (BitsLeft < 5) {
                    Idx = Bytes[i] << (5 - BitsLeft);

                    ++i;
                    if (i != Bytes.size()) {
                        Idx |= Bytes[i] >> (3 + BitsLeft);
                    }

                    Idx &= 0x1F;
                    BitsLeft += 3;
                } else {
                    Idx = Bytes[i] >> (BitsLeft - 5);

                    Idx &= 0x1F;
                    BitsLeft -= 5;
                }

                szBase32.append(1, Alphabet[Idx]);

                if (BitsLeft == 0) {
                    BitsLeft = 8;
                    ++i;
                }
            }

            if (szBase32.length() % 8) {
                size_t Padding = 8 - szBase32.length() % 8;
                szBase32.append(Padding, PaddingChar);
            }
        }

        return szBase32;
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase32DecodeA(std::string_view szBase32) {
        static constexpr std::string::value_type PaddingChar = '=';

        std::vector<OtpTypeByte> Bytes;

        if (szBase32.length()) {
            Bytes.reserve((szBase32.length() * 5 + 7) / 8);

            OtpTypeByte Byte = 0;
            OtpTypeByte BitsNeed = 8;
            for (size_t i = 0; i < szBase32.length(); ++i) {
                OtpTypeByte Idx;
                if ('A' <= szBase32[i] && szBase32[i] <= 'Z') {
                    Idx = szBase32[i] - 'A';
                } else if ('a' <= szBase32[i] && szBase32[i] <= 'z') {
                    Idx = szBase32[i] - 'a';
                } else if ('2' <= szBase32[i] && szBase32[i] <= '7') {
                    Idx = szBase32[i] - '2' + 26;
                } else if (szBase32[i] == PaddingChar) {
                    for (size_t j = i + 1; j < szBase32.length(); ++j) {
                        if (szBase32[j] != PaddingChar) {
                            throw std::invalid_argument("Invalid padding schema detected.");
                        }
                    }

                    break;
                } else {
                    throw std::invalid_argument("Non-Base32 character detected.");
                }

                if (BitsNeed >= 5) {
                    Byte |= Idx;

                    BitsNeed -= 5;
                    Byte <<= BitsNeed;
                } else {
                    Byte |= Idx >> (5 - BitsNeed);
                    Bytes.push_back(Byte);

                    BitsNeed += 3;
                    Byte = Idx << BitsNeed;
                    if (BitsNeed > 5) {
                        Byte >>= BitsNeed - 5;
                    }
                }
            }

            if (BitsNeed < 5) {
                Bytes.push_back(Byte);
            }
        }

        return Bytes;
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase32DecodeW(std::wstring_view szBase32) {
        static constexpr std::wstring::value_type PaddingChar = L'=';

        std::vector<OtpTypeByte> Bytes;

        if (szBase32.length()) {
            Bytes.reserve((szBase32.length() * 5 + 7) / 8);

            OtpTypeByte Byte = 0;
            OtpTypeByte BitsNeed = 8;
            for (size_t i = 0; i < szBase32.length(); ++i) {
                OtpTypeByte Idx;
                if (L'A' <= szBase32[i] && szBase32[i] <= L'Z') {
                    Idx = szBase32[i] - L'A';
                } else if (L'a' <= szBase32[i] && szBase32[i] <= L'z') {
                    Idx = szBase32[i] - L'a';
                } else if (L'2' <= szBase32[i] && szBase32[i] <= L'7') {
                    Idx = szBase32[i] - L'2' + 26;
                } else if (szBase32[i] == PaddingChar) {
                    for (size_t j = i + 1; j < szBase32.length(); ++j) {
                        if (szBase32[j] != PaddingChar) {
                            throw std::invalid_argument("Invalid padding schema detected.");
                        }
                    }

                    break;
                } else {
                    throw std::invalid_argument("Non-Base32 character detected.");
                }

                if (BitsNeed >= 5) {
                    Byte |= Idx;

                    BitsNeed -= 5;
                    Byte <<= BitsNeed;
                } else {
                    Byte |= Idx >> (5 - BitsNeed);
                    Bytes.push_back(Byte);

                    BitsNeed += 3;
                    Byte = Idx << BitsNeed;
                    if (BitsNeed > 5) {
                        Byte >>= BitsNeed - 5;
                    }
                }
            }

            if (BitsNeed < 5) {
                Bytes.push_back(Byte);
            }
        }

        return Bytes;
    }

#if defined(_UNICODE) || defined(UNICODE)
    [[nodiscard]]
    inline std::wstring OtpBase32Encode(const std::vector<OtpTypeByte>& Bytes) {
        return OtpBase32EncodeW(Bytes);
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase32Decode(std::wstring_view szBase32) {
        return OtpBase32DecodeW(szBase32);
    }
#else
    [[nodiscard]]
    inline std::string OtpBase32Encode(const std::vector<OtpTypeByte>& Bytes) {
        return OtpBase32EncodeA(Bytes);
    }

    [[nodiscard]]
    inline std::vector<OtpTypeByte> OtpBase32Decode(std::string_view szBase32) {
        return OtpBase32DecodeA(szBase32);
    }
#endif

}

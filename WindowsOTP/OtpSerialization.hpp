#pragma once
#include <stdlib.h>

namespace WinOTP {

    enum class OtpSerializationEndian { Little, Big };

    template<OtpSerializationEndian __Endian, typename __IntegerType>
    void OtpSerializationIntegerToBytes(__IntegerType Integer, OtpTypeAny* lpBytes) noexcept {
        static_assert(std::is_integral_v<__IntegerType>);
        static_assert(
            sizeof(__IntegerType) == 1 ||
            sizeof(__IntegerType) == 2 ||
            sizeof(__IntegerType) == 4 ||
            sizeof(__IntegerType) == 8
        );

        if constexpr (__Endian == OtpSerializationEndian::Little) {
            *reinterpret_cast<__IntegerType*>(lpBytes) = Integer;
            return;
        }

        if constexpr (__Endian == OtpSerializationEndian::Big) {
            if constexpr (sizeof(__IntegerType) == 1) {
                *reinterpret_cast<__IntegerType*>(lpBytes) = Integer;
                return;
            }

            if constexpr (sizeof(__IntegerType) == 2) {
                *reinterpret_cast<__IntegerType*>(lpBytes) = _byteswap_ushort(Integer);
                return;
            }

            if constexpr (sizeof(__IntegerType) == 4) {
                *reinterpret_cast<__IntegerType*>(lpBytes) = _byteswap_ulong(Integer);
                return;
            }

            if constexpr (sizeof(__IntegerType) == 8) {
                *reinterpret_cast<__IntegerType*>(lpBytes) = _byteswap_uint64(Integer);
                return;
            }

            __assume(0);
        }

        __assume(0);
    }

    template<OtpSerializationEndian __Endian, typename __IntegerType>
    [[nodiscard]]
    __IntegerType OtpSerializationBytesToInteger(const OtpTypeAny* lpBytes) noexcept {
        static_assert(std::is_integral_v<__IntegerType>);
        static_assert(
            sizeof(__IntegerType) == 1 ||
            sizeof(__IntegerType) == 2 ||
            sizeof(__IntegerType) == 4 ||
            sizeof(__IntegerType) == 8
        );

        if constexpr (__Endian == OtpSerializationEndian::Little) {
            return *reinterpret_cast<const __IntegerType*>(lpBytes);
        }

        if constexpr (__Endian == OtpSerializationEndian::Big) {
            if constexpr (sizeof(__IntegerType) == 1) {
                return *reinterpret_cast<const __IntegerType*>(lpBytes);
            }

            if constexpr (sizeof(__IntegerType) == 2) {
                return static_cast<__IntegerType>(
                    _byteswap_ushort(*reinterpret_cast<const __IntegerType*>(lpBytes))
                );
            }

            if constexpr (sizeof(__IntegerType) == 4) {
                return static_cast<__IntegerType>(
                    _byteswap_ulong(*reinterpret_cast<const __IntegerType*>(lpBytes))
                );
            }

            if constexpr (sizeof(__IntegerType) == 8) {
                return static_cast<__IntegerType>(
                    _byteswap_uint64(*reinterpret_cast<const __IntegerType*>(lpBytes))
                );
            }

            __assume(0);
        }

        __assume(0);
    }

}

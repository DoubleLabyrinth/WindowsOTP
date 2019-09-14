#pragma once
#include <stddef.h>
#include <stdint.h>

namespace WinOTP {

    using OtpTypeAny = void;
    using OtpTypeByte = uint8_t;
    using OtpTypeUInt8 = uint8_t;
    using OtpTypeUInt16 = uint16_t;
    using OtpTypeUInt32 = uint32_t;
    using OtpTypeUInt64 = uint64_t;
    using OtpTypeSize = size_t;

    enum class OtpEnumEndian {
        Little,
        Big
    };

    enum class OtpHashMode {
        Sha1,
        Sha256,
        Sha512
    };

}


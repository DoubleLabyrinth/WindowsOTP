#pragma once
#include "OtpGeneratorRfc4226.hpp"
#include "OtpGeneratorRfc6238.hpp"

namespace WinOTP {
    using HOTP = OtpGeneratorRfc4226;
    using TOTP = OtpGeneratorRfc6238;
}


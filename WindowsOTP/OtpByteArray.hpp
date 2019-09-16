#pragma once
#include "OtpType.hpp"
#include <windows.h>
#include <vector>

namespace WinOTP {

    using OtpByteArray = std::vector<OtpTypeByte>;

    class OtpByteArraySecure : public OtpByteArray {
    public:

        using std::vector<OtpTypeByte>::vector;

        OtpByteArraySecure(const OtpByteArray& Other) :
            OtpByteArray(Other) {}

        OtpByteArraySecure(OtpByteArray&& Other) :
            OtpByteArray(std::move(Other)) {}

        OtpByteArraySecure(const OtpByteArraySecure& Other) = default;

        OtpByteArraySecure(OtpByteArraySecure&& Other) noexcept = default;

        OtpByteArraySecure& operator=(const OtpByteArray& Other) {
            OtpByteArray::operator=(Other);
            return *this;
        }

        OtpByteArraySecure& operator=(OtpByteArray&& Other) {
            OtpByteArray::operator=(std::move(Other));
            return *this;
        }

        OtpByteArraySecure& operator=(const OtpByteArraySecure& Other) = default;

        OtpByteArraySecure& operator=(OtpByteArraySecure&& Other) = default;

        ~OtpByteArraySecure() {
            SecureZeroMemory(data(), size());
        }
    };

}


#pragma once

namespace WinOTP::Internal {

    template<typename __ClassType>
    struct OtpResourceTraitsCppObject {
        using HandleType = __ClassType*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) {
            delete Handle;
        }
    };

    template<typename __Type>
    struct OtpResourceTraitsCppArray {
        using HandleType = __Type*;

        static inline const HandleType InvalidValue = nullptr;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) {
            delete[] Handle;
        }
    };

}


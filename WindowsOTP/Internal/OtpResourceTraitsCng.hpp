#pragma once
#include <windows.h>
#include <bcrypt.h>
#include "OtpExceptionCategory.hpp"

#pragma comment(lib, "bcrypt")

namespace WinOTP::Internal {

    struct OtpResourceTraitsCngAlgHandle {
        using HandleType = BCRYPT_ALG_HANDLE;

        static inline const HandleType InvalidValue = NULL;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) {
            auto ntStatus = BCryptCloseAlgorithmProvider(Handle, 0);
            if (!BCRYPT_SUCCESS(ntStatus)) {
                throw std::system_error(
                    ntStatus,
                    OtpExceptionWinNTCategory()
                );
            }
        }
    };

    struct OtpResourceTraitsCngHashHandle {
        using HandleType = BCRYPT_HASH_HANDLE;

        static inline const HandleType InvalidValue = NULL;

        [[nodiscard]]
        static bool IsValid(const HandleType& Handle) noexcept {
            return Handle != InvalidValue;
        }

        static void Release(const HandleType& Handle) {
            auto ntStatus = BCryptDestroyHash(Handle);
            if (!BCRYPT_SUCCESS(ntStatus)) {
                throw std::system_error(
                    ntStatus,
                    OtpExceptionWinNTCategory()
                );
            }
        }
    };

}


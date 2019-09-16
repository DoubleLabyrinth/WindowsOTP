#pragma once
#include <windows.h>
#include <system_error>
#include <memory>

namespace WinOTP::Internal {

    class OtpExceptionCategoryWin32 final : public std::error_category {
    public:

        [[nodiscard]]
        virtual const char* name() const noexcept override {
            return "Win32 Exception";
        }

        [[nodiscard]]
        virtual std::string message(int _Errval) const override {
            PSTR lpszErrorText = nullptr;
            auto cchErrorText = FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL,
                _Errval,
                0,
                reinterpret_cast<PSTR>(&lpszErrorText),
                0,
                NULL
            );

            if (cchErrorText) {
                std::unique_ptr<CHAR, decltype(&::LocalFree)> lpszManagedErrorText{ lpszErrorText, ::LocalFree };
                return std::string(lpszManagedErrorText.get(), cchErrorText);
            } else {
                return std::string("N/A");
            }
        }

    };

    class OtpExceptionCategoryWinNT final : public std::error_category {
    public:

        [[nodiscard]]
        virtual const char* name() const noexcept override {
            return "NT Exception";
        }

        [[nodiscard]]
        virtual std::string message(int _Errval) const override {
            PSTR lpszErrorText = nullptr;
            auto cchErrorText = FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                GetModuleHandle(TEXT("ntdll.dll")),
                _Errval,
                0,
                reinterpret_cast<PSTR>(&lpszErrorText),
                0,
                NULL
            );

            if (cchErrorText) {
                std::unique_ptr<CHAR, decltype(&::LocalFree)> lpszManagedErrorText{ lpszErrorText, ::LocalFree };
                return std::string(lpszManagedErrorText.get(), cchErrorText);
            } else {
                return std::string("N/A");
            }
        }

    };

    [[nodiscard]]
    inline const OtpExceptionCategoryWin32& OtpExceptionWin32Category() noexcept {
        static OtpExceptionCategoryWin32 Category;
        return Category;
    }

    [[nodiscard]]
    inline const OtpExceptionCategoryWinNT& OtpExceptionWinNTCategory() noexcept {
        static OtpExceptionCategoryWinNT Category;
        return Category;
    }

}


#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <mutex>
#include "OtpExceptionCategory.hpp"
#include "OtpResource.hpp"
#include "OtpResourceTraitsGeneric.hpp"
#include "OtpResourceTraitsCng.hpp"

#pragma comment(lib, "bcrypt")

namespace WinOTP::Internal {

    enum class OtpCngHashEnum {
        Sha1,
        Sha256,
        Sha384,
        Sha512
    };

    class OtpCngHashProvider : private OtpResource<OtpResourceTraitsCngAlgHandle> {
    private:

        DWORD m_HashObjectSize;
        DWORD m_HashSize;

        OtpCngHashProvider() noexcept :
            m_HashObjectSize(0),
            m_HashSize(0) {}

    public:

        static OtpCngHashProvider* CreateProvider(PCWSTR lpszAlgId, PCWSTR lpszImplementation, DWORD dwFlags) {
            OtpResource<OtpResourceTraitsCppObject<OtpCngHashProvider>> Instance(new OtpCngHashProvider());

            auto ntStatus = BCryptOpenAlgorithmProvider(Instance->GetAddressOf(), lpszAlgId, lpszImplementation, dwFlags);
            if (!BCRYPT_SUCCESS(ntStatus)) {
                throw std::system_error(
                    ntStatus,
                    OtpExceptionWinNTCategory()
                );
            }

            ULONG cbReturnData;
            ntStatus = BCryptGetProperty(Instance->Get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&Instance->m_HashObjectSize), sizeof(DWORD), &cbReturnData, 0);
            if (!BCRYPT_SUCCESS(ntStatus)) {
                throw std::system_error(
                    ntStatus,
                    OtpExceptionWinNTCategory()
                );
            }

            ntStatus = BCryptGetProperty(Instance->Get(), BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&Instance->m_HashSize), sizeof(DWORD), &cbReturnData, 0);
            if (!BCRYPT_SUCCESS(ntStatus)) {
                throw std::system_error(
                    ntStatus,
                    OtpExceptionWinNTCategory()
                );
            }

            return Instance.Transfer();
        }

        BCRYPT_ALG_HANDLE GetNativeHandle() const noexcept {
            return Get();
        }

        DWORD GetHashObjectSize() const noexcept {
            return m_HashObjectSize;
        }

        DWORD GetHashSize() const noexcept {
            return m_HashSize;
        }

        ~OtpCngHashProvider() {
            m_HashSize = 0;
            m_HashObjectSize = 0;
        }
    };

    const OtpCngHashProvider& OtpCngCategoryHmac(OtpCngHashEnum HashAlgorithm) {
        static std::mutex InitializeMutex;
        static OtpResource HmacSha1Provider(OtpResourceTraitsCppObject<OtpCngHashProvider>{});
        static OtpResource HmacSha256Provider(OtpResourceTraitsCppObject<OtpCngHashProvider>{});
        static OtpResource HmacSha384Provider(OtpResourceTraitsCppObject<OtpCngHashProvider>{});
        static OtpResource HmacSha512Provider(OtpResourceTraitsCppObject<OtpCngHashProvider>{});

        switch (HashAlgorithm) {
            case OtpCngHashEnum::Sha1:
                if (HmacSha1Provider.IsValid() == false) {
                    std::lock_guard InitLock(InitializeMutex);

                    if (HmacSha1Provider.IsValid() == false) {
                        OtpCngHashProvider* volatile lpInstance = OtpCngHashProvider::CreateProvider(
                            BCRYPT_SHA1_ALGORITHM,
                            NULL,
                            BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG
                        );

                        HmacSha1Provider.TakeOver(const_cast<OtpCngHashProvider*>(lpInstance));
                    }
                }
                
                return *HmacSha1Provider.Get();
            case OtpCngHashEnum::Sha256:
                if (HmacSha256Provider.IsValid() == false) {
                    std::lock_guard InitLock(InitializeMutex);

                    if (HmacSha256Provider.IsValid() == false) {
                        OtpCngHashProvider* volatile lpInstance = OtpCngHashProvider::CreateProvider(
                            BCRYPT_SHA256_ALGORITHM,
                            NULL,
                            BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG
                        );

                        HmacSha256Provider.TakeOver(const_cast<OtpCngHashProvider*>(lpInstance));
                    }
                }

                return *HmacSha256Provider.Get();
            case OtpCngHashEnum::Sha384:
                if (HmacSha384Provider.IsValid() == false) {
                    std::lock_guard InitLock(InitializeMutex);

                    if (HmacSha384Provider.IsValid() == false) {
                        OtpCngHashProvider* volatile lpInstance = OtpCngHashProvider::CreateProvider(
                            BCRYPT_SHA384_ALGORITHM,
                            NULL,
                            BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG
                        );

                        HmacSha384Provider.TakeOver(const_cast<OtpCngHashProvider*>(lpInstance));
                    }
                }

                return *HmacSha384Provider.Get();
            case OtpCngHashEnum::Sha512:
                if (HmacSha512Provider.IsValid() == false) {
                    std::lock_guard InitLock(InitializeMutex);

                    if (HmacSha512Provider.IsValid() == false) {
                        OtpCngHashProvider* volatile lpInstance = OtpCngHashProvider::CreateProvider(
                            BCRYPT_SHA512_ALGORITHM,
                            NULL,
                            BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG
                        );

                        HmacSha512Provider.TakeOver(const_cast<OtpCngHashProvider*>(lpInstance));
                    }
                }

                return *HmacSha512Provider.Get();
            default:
                __assume(0);
        }
    }

}


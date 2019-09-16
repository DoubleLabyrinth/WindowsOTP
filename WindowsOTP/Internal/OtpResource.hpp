#pragma once
#include <type_traits>
#include <utility>

namespace WinOTP::Internal {

    template<typename __ResourceTraits>
    class OtpResource {
    public:

        using HandleType = typename __ResourceTraits::HandleType;
        
    private:

        HandleType m_Handle;

    public:

        OtpResource() noexcept :
            m_Handle(__ResourceTraits::InvalidValue) {}

        OtpResource(HandleType Handle) noexcept :
            m_Handle(Handle) {}

        OtpResource(__ResourceTraits) noexcept :
            m_Handle(__ResourceTraits::InvalidValue) {}

        OtpResource(__ResourceTraits, HandleType Handle) noexcept :
            m_Handle(Handle) {}

        //
        // copy construct is not allowed.
        //
        OtpResource(const OtpResource& Other) = delete;

        //
        // move construct is allowed.
        //
        OtpResource(OtpResource&& Other) noexcept :
            m_Handle(std::move(Other.m_Handle)) { Other.m_Handle = __ResourceTraits::InvalidValue; }

        //
        // copy assignment is not allowed.
        //
        OtpResource& operator=(const OtpResource& Other) = delete;

        //
        // move assignment is allowed.
        //
        OtpResource& operator=(OtpResource&& Other) noexcept {
            if (this != std::addressof(Other)) {
                if (__ResourceTraits::IsValid(m_Handle)) {
                    // if throws exception, just suppress it and terminate process
                    __ResourceTraits::Release(m_Handle);
                }

                m_Handle = std::move(Other.m_Handle);

                Other.m_Handle = __ResourceTraits::InvalidValue;
            }

            return *this;
        }

        template<bool __Enable = std::is_pointer_v<HandleType>>
        [[nodiscard]]
        std::enable_if_t<__Enable, HandleType> operator->() const noexcept {
            return m_Handle;
        }

        [[nodiscard]]
        bool IsValid() const noexcept {
            return __ResourceTraits::IsValid(m_Handle);
        }

        [[nodiscard]]
        HandleType Get() const noexcept {
            return m_Handle;
        }

        template<typename __ReturnType = HandleType*>
        [[nodiscard]]
        __ReturnType GetAddressOf() noexcept {
            return reinterpret_cast<__ReturnType>(&m_Handle);
        }

        template<typename __AsType>
        [[nodiscard]]
        __AsType As() const noexcept {
            return reinterpret_cast<__AsType>(m_Handle);
        }

        void TakeOver(const HandleType& Handle) {
            if (__ResourceTraits::IsValid(m_Handle)) {
                __ResourceTraits::Release(m_Handle);
            }

            m_Handle = Handle;
        }

        void Discard() noexcept {
            if (__ResourceTraits::IsValid(m_Handle)) {
                m_Handle = __ResourceTraits::InvalidValue;
            }
        }

        [[nodiscard]]
        HandleType Transfer() noexcept {
            HandleType tmp = m_Handle;
            m_Handle = __ResourceTraits::InvalidValue;
            return tmp;
        }

        void Release() {
            if (__ResourceTraits::IsValid(m_Handle)) {
                __ResourceTraits::Release(m_Handle);
                m_Handle = __ResourceTraits::InvalidValue;
            }
        }

        ~OtpResource() {
            Release();
        }
    };

    template<typename __ResourceTraits, typename __DeleterType>
    class OtpResourceEx {
    public:

        using HandleType = typename __ResourceTraits::HandleType;
        using DeleterType = __DeleterType;

    private:

        HandleType  m_Handle;
        DeleterType m_Deleter;

    public:

        template<typename __DeleterArgType>
        OtpResourceEx(__DeleterArgType&& Deleter) noexcept :
            m_Handle(__ResourceTraits::InvalidValue),
            m_Deleter(std::forward<__DeleterArgType>(Deleter)) {}

        template<typename __DeleterArgType>
        OtpResourceEx(HandleType Handle, __DeleterArgType&& Deleter) noexcept :
            m_Handle(Handle),
            m_Deleter(std::forward<__DeleterArgType>(Deleter)) {}

        template<typename __DeleterArgType>
        OtpResourceEx(__ResourceTraits, __DeleterArgType&& Deleter) noexcept :
            m_Handle(__ResourceTraits::InvalidValue),
            m_Deleter(std::forward<__DeleterArgType>(Deleter)) {}

        template<typename __DeleterArgType>
        OtpResourceEx(__ResourceTraits, HandleType Handle, __DeleterArgType&& Deleter) noexcept :
            m_Handle(Handle),
            m_Deleter(std::forward<__DeleterArgType>(Deleter)) {}

        //
        // copy construct is not allowed.
        //
        OtpResourceEx(const OtpResourceEx& Other) = delete;

        //
        // move construct is allowed.
        //
        OtpResourceEx(OtpResourceEx&& Other) noexcept :
            m_Handle(std::move(Other.m_Handle)),
            m_Deleter(std::move(Other.m_Deleter)) { Other.m_Handle = __ResourceTraits::InvalidValue; }

        //
        // copy assignment is not allowed.
        //
        OtpResourceEx& operator=(const OtpResourceEx& Other) = delete;

        //
        // move assignment is allowed.
        //
        OtpResourceEx& operator=(OtpResourceEx&& Other) noexcept {
            if (this != std::addressof(Other)) {
                if (__ResourceTraits::IsValid(m_Handle)) {
                    // if throws exception, just suppress it and terminate process
                    m_Deleter(m_Handle);
                }

                m_Handle = std::move(Other.m_Handle);
                m_Deleter = std::move(Other.m_Deleter);

                Other.m_Handle = __ResourceTraits::InvalidValue;
            }

            return *this;
        }

        template<bool __Enable = std::is_pointer_v<HandleType>>
        [[nodiscard]]
        std::enable_if_t<__Enable, HandleType> operator->() const noexcept {
            return m_Handle;
        }

        [[nodiscard]]
        bool IsValid() const noexcept {
            return __ResourceTraits::IsValid(m_Handle);
        }

        [[nodiscard]]
        HandleType Get() const noexcept {
            return m_Handle;
        }

        template<typename __ReturnType = HandleType*>
        [[nodiscard]]
        __ReturnType GetAddressOf() noexcept {
            return reinterpret_cast<__ReturnType>(&m_Handle);
        }

        template<typename __AsType>
        [[nodiscard]]
        __AsType As() const noexcept {
            return reinterpret_cast<__AsType>(m_Handle);
        }

        void TakeOver(const HandleType& Handle) {
            if (__ResourceTraits::IsValid(m_Handle)) {
                m_Deleter(m_Handle);
            }

            m_Handle = Handle;
        }

        void Discard() noexcept {
            if (__ResourceTraits::IsValid(m_Handle)) {
                m_Handle = __ResourceTraits::InvalidValue;
            }
        }

        [[nodiscard]]
        HandleType Transfer() noexcept {
            HandleType tmp = m_Handle;
            m_Handle = __ResourceTraits::InvalidValue;
            return tmp;
        }

        void Release() {
            if (__ResourceTraits::IsValid(m_Handle)) {
                m_Deleter(m_Handle);
                m_Handle = __ResourceTraits::InvalidValue;
            }
        }

        ~OtpResourceEx() {
            Release();
        }
    };

}


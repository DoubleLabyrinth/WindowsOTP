#include <tchar.h>
#include <windows.h>
#include <WinOTP.hpp>

#define OTP_SECRET TEXT("base32secret3232")

int _tmain(int argc, PTSTR argv[]) {
    WinOTP::HOTP Hotp;
    WinOTP::TOTP Totp;

    Hotp.ImportSecretBase32(OTP_SECRET);
    Totp.ImportSecretBase32(OTP_SECRET);

    _tprintf_s(TEXT("Secret     = %s\n"), OTP_SECRET);
    _tprintf_s(TEXT("Hotp(0)    = %s\n"), Hotp.GenerateCodeString(0).c_str());
    _tprintf_s(TEXT("Hotp(1)    = %s\n"), Hotp.GenerateCodeString(1).c_str());
    _tprintf_s(TEXT("Hotp(1401) = %s\n"), Hotp.GenerateCodeString(1401).c_str());
    _tprintf_s(TEXT("Totp       = %s\n"), Totp.GenerateCodeString().c_str());

    return 0;
}


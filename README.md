# Windows OTP

A C++17 based OTP header-only library for Windows.

~~__Minimum OS requirement: Windows10.__ Because it uses `BCryptHash` API.~~

__Minimum OS requirement: Windows Vista.__ Because it uses Windows CNG APIs.

## 1. Example

Code:

```cpp
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
```

Output:

```
Secret     = base32secret3232
Hotp(0)    = 260182
Hotp(1)    = 055283
Hotp(1401) = 316439
Totp       = 261656     # this one based on your time.
```

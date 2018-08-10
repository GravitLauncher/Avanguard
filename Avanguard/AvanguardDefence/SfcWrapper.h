#pragma once

using _SfcIsFileProtected = BOOL (WINAPI*)(HANDLE RpcHandle, LPCWSTR Path);

class Sfc final {
private:
    static _SfcIsFileProtected __SfcIsFileProtected;
    static BOOL Initialized;
public:
    static BOOL Initialize();
    static BOOL IsFileProtected(LPCWSTR Path);
};
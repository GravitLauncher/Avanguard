#pragma once

BOOL InitWinTrust();
BOOL IsFileSigned(LPCWSTR FilePath, BOOL CheckRevocation);
//BOOL VerifyEmbeddedSignature(LPCWSTR FilePath);
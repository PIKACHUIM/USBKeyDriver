using System.Runtime.InteropServices;

namespace USBKey.Core.UsbKey;

// PKCS#11 函数委托定义
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Initialize_t(IntPtr pInitArgs);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Finalize_t(IntPtr pReserved);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GetInfo_t(IntPtr pInfo);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GetSlotList_t(byte tokenPresent, IntPtr pSlotList, ref uint pulCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GetSlotInfo_t(uint slotID, IntPtr pInfo);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GetTokenInfo_t(uint slotID, IntPtr pInfo);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_OpenSession_t(uint slotID, uint flags, IntPtr pApplication, IntPtr notify, ref uint phSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_CloseSession_t(uint hSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_CloseAllSessions_t(uint slotID);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GetSessionInfo_t(uint hSession, IntPtr pInfo);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Login_t(uint hSession, uint userType, IntPtr pPin, uint ulPinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Logout_t(uint hSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_CreateObject_t(uint hSession, IntPtr pTemplate, uint ulCount, ref uint phObject);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_DestroyObject_t(uint hSession, uint hObject);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GetAttributeValue_t(uint hSession, uint hObject, IntPtr pTemplate, uint ulCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_SetAttributeValue_t(uint hSession, uint hObject, IntPtr pTemplate, uint ulCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_FindObjectsInit_t(uint hSession, IntPtr pTemplate, uint ulCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_FindObjects_t(uint hSession, IntPtr phObject, uint ulMaxObjectCount, ref uint pulObjectCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_FindObjectsFinal_t(uint hSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_EncryptInit_t(uint hSession, IntPtr pMechanism, uint hKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Encrypt_t(uint hSession, IntPtr pData, uint ulDataLen, IntPtr pEncryptedData, ref uint pulEncryptedDataLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_DecryptInit_t(uint hSession, IntPtr pMechanism, uint hKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Decrypt_t(uint hSession, IntPtr pEncryptedData, uint ulEncryptedDataLen, IntPtr pData, ref uint pulDataLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_SignInit_t(uint hSession, IntPtr pMechanism, uint hKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Sign_t(uint hSession, IntPtr pData, uint ulDataLen, IntPtr pSignature, ref uint pulSignatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_VerifyInit_t(uint hSession, IntPtr pMechanism, uint hKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_Verify_t(uint hSession, IntPtr pData, uint ulDataLen, IntPtr pSignature, uint ulSignatureLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GenerateKeyPair_t(uint hSession, IntPtr pMechanism, IntPtr pPublicKeyTemplate, uint ulPublicKeyAttributeCount, IntPtr pPrivateKeyTemplate, uint ulPrivateKeyAttributeCount, ref uint phPublicKey, ref uint phPrivateKey);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_GenerateRandom_t(uint hSession, IntPtr pRandomData, uint ulRandomLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_InitToken_t(uint slotID, IntPtr pPin, uint ulPinLen, IntPtr pLabel);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_InitPIN_t(uint hSession, IntPtr pPin, uint ulPinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint C_SetPIN_t(uint hSession, IntPtr pOldPin, uint ulOldLen, IntPtr pNewPin, uint ulNewLen);

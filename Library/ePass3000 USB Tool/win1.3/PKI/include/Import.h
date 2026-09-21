/*
[]======================================================================[]

	Copyright(C) 1998-2003, Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	import.h

DESC:
	

REVISION:
	2002-10-18 [Yubo Zheng]
		Created.
	2003-04-22 [Euphen Liu] 
		Update the interface.
[]======================================================================[]
*/

#define IN
#define OUT

#include <windows.h>

#ifdef __cplusplus
extern "C"{
#endif

// The return value is the same as the PKCS#11 return value.
// CKR_OK (0) means all works fine.

// not import certificate chain
DWORD ImportCertFromP12FileWithoutChain(
	IN const char* szCertFileName,			// Must include full path
	IN const char* szPassword,				// The cert file password
	IN const char* szUserPIN,				// The user-PIN of the token.
	IN const char* szContainerName			//specify the ContainerName,if szContainerName, 
											//we use default containerName
);

// not import certificate chain
DWORD ImportCertFromMemWithoutChain(	
	IN const unsigned char* pCertBuffer,	// Only .p12/.pfx format
	IN DWORD dwBufferLen,					// Length of the cert buffer.
	IN const char* szPassword,				// The cert password
	IN const char* szUserPIN,				// The user-PIN of the token.
	IN const char* szContainerName			//specify the ContainerName,if szContainerName, 
											//we use default containerName
);

// import certificate chain
DWORD ImportCertFromP12File(
	IN const char* szCertFileName,			// Must include full path
	IN const char* szPassword,				// The cert file password
	IN const char* szUserPIN,				// The user-PIN of the token.
	IN const char* szContainerName			//specify the ContainerName,if szContainerName, 
											//we use default containerName
);

// import certificate chain
DWORD ImportCertFromMem(	
	IN const unsigned char* pCertBuffer,	// Only .p12/.pfx format
	IN DWORD dwBufferLen,					// Length of the cert buffer.
	IN const char* szPassword,				// The cert password
	IN const char* szUserPIN,				// The user-PIN of the token.
	IN const char* szContainerName			//specify the ContainerName,if szContainerName, 
											//we use default containerName
);

#ifdef __cplusplus
}
#endif
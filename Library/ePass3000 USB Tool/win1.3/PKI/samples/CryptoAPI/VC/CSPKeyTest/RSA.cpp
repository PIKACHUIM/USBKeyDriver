/*
[]=========================================================================[]

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	RSA.cpp

DESC:
	Test RSA key: public key encrypt and private key decrypt!
[]=========================================================================[]
*/

#include "stdafx.h"
#include "RSA.h"

#define DATALEN 100

CRSA::CRSA()
{
}

CRSA::~CRSA()
{
}

void CRSA::TestRSA(void)
{
	HCRYPTPROV hCryptProv = NULL;

	cout << endl << "Test CSP: " << TEST_CSP_NAME << endl << endl;

	// Create a keyset(aka container), if the keyset already exists,
	// delete it and re-create it.

	BeginAction("CryptAcquireContext() CRYPT_NEWKEYSET");
	if(!CryptAcquireContext(&hCryptProv,
				CONTAINER,
				TEST_CSP_NAME,
				PROV_RSA_FULL,
				CRYPT_NEWKEYSET))
	{
		DWORD dwLastErr = GetLastError();
		ActionFailed(dwLastErr);

		if(0x8009000F == dwLastErr) //  Object already exists.
		{
			BeginAction("CryptAcquireContext() CRYPT_DELETEKEYSET");
			if(!CryptAcquireContext(&hCryptProv,
						CONTAINER,
						TEST_CSP_NAME,
						PROV_RSA_FULL,
						CRYPT_DELETEKEYSET))
			{
				ActionFailed(GetLastError());
				return;
			}
			else
			{
				ActionSuccess();
				BeginAction("CryptAcquireContext() CRYPT_NEWKEYSET");
				if(!CryptAcquireContext(&hCryptProv,
							CONTAINER,
							TEST_CSP_NAME,
							PROV_RSA_FULL,
							CRYPT_NEWKEYSET))
				{
					ActionFailed(dwLastErr);
					return;
				}
				else
				{
					ActionSuccess();
				}
			}
		}
		else
			return;
	}
	else
	{
		ActionSuccess();
	}

	// Hold the handle and release when this function return.
	HCRYPTPROV_Holder holder(hCryptProv);

	HCRYPTKEY hKey;
	BeginAction("CryptGenKey()");
	if(!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, 0, &hKey))
	{
		ActionFailed(GetLastError());
		return;
	}
	else
	{
		ActionSuccess();
	}

	BYTE pData[DATALEN] = {0};
	unsigned long ulDataLen = DATALEN;
	DWORD ulEncryptedLen = ulDataLen;
	BYTE *pOut = NULL;
	for(int i = 0; i < DATALEN; i++)
	{
		pData[i] = i % 255;
	}

	cout << "Data to be encrypt:" << endl;
	ShowData(pData, ulDataLen);

	BeginAction("CryptEncrypt()");
	if(!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &ulEncryptedLen, ulDataLen))
	{
		ActionFailed(GetLastError());
		return;
	}
	else
	{
		ActionSuccess();
	}

	pOut = new BYTE[ulEncryptedLen];

	memset(pOut, 0, ulEncryptedLen);
	memcpy(pOut, pData, ulDataLen);
	DWORD ulTemp = ulDataLen;
	ulDataLen = ulEncryptedLen;
	ulEncryptedLen = ulTemp;

	BeginAction("CryptEncrypt()");
	if(!CryptEncrypt(hKey, 0, TRUE, 0, pOut, &ulEncryptedLen, ulDataLen))
	{
		delete[] pOut;
		pOut = NULL;
		ActionFailed(GetLastError());
		return;
	}
	else
	{
		ActionSuccess();
//		for(DWORD i = 0; i < ulEncryptedLen; i++)
//		{
//			printf("%d=%d, ", i, pOut[i]);
//		}
		cout << "Data encrypted:" << endl;
		ShowData(pOut, ulEncryptedLen);
	}

	BeginAction("CryptDecrypt()");
	if(!CryptDecrypt(hKey, 0, TRUE, 0, pOut, &ulEncryptedLen))
	{
		delete[] pOut;
		pOut = 0;
		ActionFailed(GetLastError());
		return;
	}
	else
	{
		ActionSuccess();
//		for(DWORD i = 0; i < ulEncryptedLen; i++)
//		{
//			if(pOut[i] != i % 255)
//			{
//				printf("\n%d=error!", i);
//			}
//			else
//			{
//				printf("%d=%d, ", i, pOut[i]);
//			}
//		}
		cout << "Data to decrypted:" << endl;
		ShowData(pOut, ulEncryptedLen);
	}

	if(0 != memcmp(pData, pOut, ulEncryptedLen))
	{
		delete[] pOut;
		pOut = NULL;
		//printf("\n....RSA key Encryption and Decryption Failed!....\n");
		cout << "Data not equal, encrypt/decrypt failed." << endl;
	}
}

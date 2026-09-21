/*
[]=========================================================================[]

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	dhkeygentest.cpp

DESC:
	implementation of the DHkeyGenTest class.
[]=========================================================================[]
*/

#include "DHKeyGenTest.h"
#include "common.h"
DHKeyGenTest::DHKeyGenTest(char* dll_file_path):CBaseAll(dll_file_path)
{

}

DHKeyGenTest::~DHKeyGenTest()
{

}

//Include testing C_GenerateKeyPair and C_DeriveKey with DH Alg!
void DHKeyGenTest::DHKeyTest()
{
	if(CKR_OK != BaseAllStart())
		return;
	START_OP("Now test DH key pair generate and derive a security key...\n");
	CK_RV rv = CKR_OK;
	CK_BYTE bCipherBuffer[MODULUS_BIT_LENGTH] = {0};
	CK_ULONG ulCipherLen = 0;
	CK_BYTE bRestoredMsg[MODULUS_BIT_LENGTH] = {0};
	CK_ULONG ulRestoredMsgLen = 0;
	
	CK_BYTE pbMsg[] = "UsbToken[ePass] DH Key Test..../////[Yubo]!";
	CK_ULONG ulMsgLen = strlen((const char *)pbMsg);

	do {
		//init the DH key pair generate template1(Part1):
		CK_OBJECT_HANDLE hPubKey = 0, hPriKey = 0;
		CK_MECHANISM keypairgenmechanism = {CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

		CK_BYTE ucBase[1]={0x02};
		CK_BYTE ucPrime[32]={0x98,0x9c,0x2b,0x29,0xeb,0xe5,0x5,\
							0xc7,0x72,0xa0,0xa8,0x1,0x12,0x12,\
							0x2d,0x8,0x8f,0x9f,0xbc,0x9f,0xef,\
							0x85,0x18,0x1f,0x19,0x6f,0x82,0x3c,\
							0xc9,0xf9,0x54,0xfb};

		CK_ULONG ulBits = 192;
		//dh1 public template:
		CK_ATTRIBUTE dhTemplatePub[] =	{
			{CKA_PRIME, ucPrime, 32},
			{CKA_BASE, ucBase, 1},
		};
		CK_ULONG ulCountTemPub = 2;
		//dh1 private template: 
		CK_ATTRIBUTE dhTemplatePri [] = {
			{CKA_PRIME, ucPrime, 32}, 
			{CKA_BASE, ucBase, 1},
			{CKA_VALUE_BITS, &ulBits, sizeof(ulBits)},
		};
		CK_ULONG ulCountTemPri = 3; 
		//Generate key pair:
		START_OP("Now calling C_GenerateKeyPair() for generating keys...");
		rv = m_gToken->C_GenerateKeyPair(hSession, &keypairgenmechanism, dhTemplatePub, ulCountTemPub,
										dhTemplatePri, ulCountTemPri, &hPubKey, &hPriKey);
		assert(hPubKey);
		assert(hPriKey);
		CHECK_OP(rv);

		//Get 2nd public value:
		CK_ATTRIBUTE pTemplate[] = {
			{CKA_VALUE, NULL_PTR, 0},
		};
		START_OP("Read for Getting 2nd part's public key...");
		rv = m_gToken->C_GetAttributeValue(hSession, hPubKey, pTemplate, 1);
		CHECK_OP(rv);
		int ulValue = pTemplate[0].ulValueLen;
		CK_BYTE Buf[512] = {0};
		CK_BYTE_PTR ucValue = Buf;
		memset(ucValue, 0, ulValue);
		pTemplate[0].pValue = ucValue;
		START_OP("Get 2nd public Key...");
		rv = m_gToken->C_GetAttributeValue(hSession, hPubKey, pTemplate, 1);
		CHECK_OP(rv);

		//Derive key:
		//Init the 2nd part's publice key form the 2nd's public template:
		CK_KEY_TYPE keytype = CKK_DES;
		CK_OBJECT_CLASS objclass = CKO_SECRET_KEY;
		CK_BBOOL bTrue = true;
		CK_ATTRIBUTE dh2ndTemplatePub[] = {
			{CKA_CLASS, &objclass, sizeof(CK_OBJECT_CLASS)},
			{CKA_KEY_TYPE, &keytype, sizeof(CK_KEY_TYPE)},
			{CKA_DERIVE, &bTrue, sizeof(CK_BBOOL)},
		};
		CK_ULONG ul2ndCount = 3;
		CK_OBJECT_HANDLE hDeriveKey = 0;
		CK_MECHANISM derivekeymechanism = {CKM_DH_PKCS_DERIVE, &pTemplate, sizeof(pTemplate)};

		START_OP("Next is calling C_DeriveKey()...");
		rv = m_gToken->C_DeriveKey(hSession, &derivekeymechanism,
									hPriKey, dh2ndTemplatePub, ul2ndCount, &hDeriveKey);
		CHECK_OP(rv);

		//Test the Key which just derive from the 2 Parts' keys:
		CK_BYTE iv[8] = {'y','b','z','e','p','a','s','s'};
		CK_MECHANISM ckMechanism = {CKM_DES_CBC_PAD, iv, sizeof(iv)};
		
		START_OP("Encrypting initialize with DH...");
		rv =  m_gToken->C_EncryptInit(hSession, &ckMechanism, hDeriveKey); 
		CHECK_OP(rv);
			
		START_OP("Encrypt the message with DH....")
		rv =  m_gToken->C_Encrypt(hSession, pbMsg, ulMsgLen, NULL, &ulCipherLen);
		rv =  m_gToken->C_Encrypt(hSession, pbMsg, ulMsgLen, bCipherBuffer, &ulCipherLen);
		ulMsgLen = ulCipherLen;
		CHECK_OP(rv);
			
		SHOW_INFO("\nEncrypt result:\n");
		ShowData(bCipherBuffer, ulCipherLen);
		
		START_OP("Decrypting initialize with DH...");
		rv =  m_gToken->C_DecryptInit(hSession, &ckMechanism, hDeriveKey);
		CHECK_OP(rv);
			
		START_OP("Decrypt the message with DH....");
		ulCipherLen =  ulMsgLen;
		rv =  m_gToken->C_Decrypt(hSession, bCipherBuffer, ulCipherLen, NULL, &ulRestoredMsgLen);
		rv =  m_gToken->C_Decrypt(hSession, bCipherBuffer, ulCipherLen, bRestoredMsg, &ulRestoredMsgLen);
		CHECK_OP(rv);
		// Decrypt a message. 
		SHOW_INFO("\nThe message decrypted is \"");
		ShowData(bRestoredMsg, ulRestoredMsgLen);
		
		START_OP("Verify the message After DH key...");
		if(0 == memcmp(pbMsg, bRestoredMsg, ulRestoredMsgLen))
		{
			CHECK_OP(CKR_OK);
		}
		else
			SHOW_INFO("....[FAILED]\n");
	} while(0);
	BaseAllEnd();
}

// DeviceManage.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <Guomi/SKFAPI.h>

#pragma comment(lib,"..\\..\\..\\..\\Lib\\lib_x86\\ShuttleCsp11_3000GM.lib")

void PrintError(char *FunName,ULONG ErrorCode,char *Buf=NULL);

ULONG GetDevInfo(DEVHANDLE *phDev);
ULONG AppManage(DEVHANDLE hDev,HAPPLICATION *phApp);
ULONG RasKeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp);
ULONG ImportRSAKeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp);
ULONG SM2KeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp);
ULONG ImportSM2KeyPair_Test(DEVHANDLE hDev,HAPPLICATION hApp);
ULONG ImportSessionKey_Test(DEVHANDLE hDev,HAPPLICATION hApp);

int main(int argc, char* argv[])
{

	DEVHANDLE hDev;
	HAPPLICATION hApp;
	ULONG rv;

	rv = GetDevInfo(&hDev);
	if(rv)
	{
		return 0;
	}
	rv = AppManage(hDev,&hApp);
	if(rv)
	{
		return 0;
	}
	rv = RasKeyPairTest(hDev,hApp);
	if(rv)
	{
		return 0;
	}

	rv = ImportRSAKeyPairTest(hDev,hApp);
	if(rv)
	{
		return 0;
	}

	
	rv = SM2KeyPairTest(hDev,hApp);
	if(rv)
	{
		return 0;
	}	
	rv = ImportSM2KeyPair_Test(hDev,hApp);
	if(rv)
	{
		return 0;
	}

	rv = ImportSessionKey_Test(hDev,hApp);
	if(rv)
	{
		return 0;
	}
	return 0;
}


ULONG GetDevInfo(DEVHANDLE *phDev)
{
	ULONG rv=0;

	char *pbDevList= 0;
	ULONG ulDevListLen = 0;

	rv = SKF_EnumDev(1,pbDevList,&ulDevListLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EnumDev",rv);
		return rv;		
	}

	if(ulDevListLen <2)
	{
		printf("No Device!\n");
		return -1;
	}
	
	pbDevList = (char *)malloc(ulDevListLen);
	if(pbDevList == NULL)
	{
		printf("Memory Error!");
		return -1;
	}
	rv = SKF_EnumDev(1,pbDevList,&ulDevListLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EnumDev",rv,pbDevList);
		return rv;		
	}

    char *pp = pbDevList;
	while(pbDevList+ulDevListLen - pp)
	{
		if(strlen(pp))
		{
			printf("find Device %s\n",pp);
			pp+=strlen(pp);
		}
		else
		{
			pp++;
		}
	}

	pp = 0;

	
	DEVHANDLE hDev;

	rv = SKF_ConnectDev(pbDevList,&hDev);
	if(rv)
	{
		PrintError("SKF_ConnectDev",rv,pbDevList);
		return rv;	

	}
	printf("Connect Device %s\n",pbDevList);
    *phDev = hDev;

	if(pbDevList)
		free(pbDevList);

	return SAR_OK;

}

ULONG AppManage(DEVHANDLE hDev,HAPPLICATION *phApp)
{
	DWORD rv = 0;

	DEVINFO  devInfo;
	memset((char *)&devInfo,0x00,sizeof(DEVINFO));
	
	rv = SKF_GetDevInfo(hDev,&devInfo);
	if(rv)
	{
		PrintError("SKF_GetDevInfo",rv);
		return rv;	
		
	}
	DWORD dwAuthAlgId = devInfo.DevAuthAlgId;
	HANDLE hKey;
	unsigned char pbAuthKey[16]={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};    //初始的设备认证密钥,可以修改

	////////////////////////////////////////////////////
	//这一点计算设备认证值时最好是不要使用这种方式，而是使用其他的方法如使用其它的设备计算结果
	rv = SKF_SetSymmKey(hDev,pbAuthKey,dwAuthAlgId,&hKey);
	if(rv)
	{
		PrintError("SKF_SetSymmKey",rv);
		return rv;
	}
	BLOCKCIPHERPARAM EncryptParam;
	memset((char *)&EncryptParam,0x00,sizeof(BLOCKCIPHERPARAM));
	rv = SKF_EncryptInit(hKey,EncryptParam);
	if(rv)
	{
		PrintError("SKF_EncryptInit",rv);
		return rv;
	}

	unsigned char pbRandom[32]={0},pbAuthValue[32]={0};
	ULONG ulAuthValueLen =32;

	rv = SKF_GenRandom(hDev,pbRandom,8);
	if(rv)
	{
		PrintError("SKF_GenRandom",rv);
		return rv;
	}

	rv = SKF_Encrypt(hKey,pbRandom,16,pbAuthValue,&ulAuthValueLen);
	if(rv)
	{
		PrintError("SKF_Encrypt",rv);
		return rv;
	}

	rv = SKF_DevAuth(hDev,pbAuthValue,ulAuthValueLen);
	if(rv)
	{
		PrintError("SKF_DevAuth",rv);
		return rv;
	}

	char *szAppList = NULL;
	ULONG ulAppListLen = 0;

	rv= SKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv);
		return rv;
	}

	if(ulAppListLen < 2)
	{
		printf("No Application!\n");
		return -1;
	}
	szAppList = (char *)malloc(ulAppListLen);
	rv = SKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv,szAppList);
		return rv;
	}
	printf("Find Application：%s\n",szAppList);

	///////现在设备中就一个应用，
	rv = SKF_DeleteApplication(hDev,szAppList);
	if(rv)
	{
		PrintError("SKF_DeleteApplication",rv,szAppList);
		return rv;
	}

	printf("Delete Application %s succeed!\n",szAppList);

	char szAppName[32]={0};
	memcpy(szAppName,"EnterSafe",9);
	rv = SKF_CreateApplication(hDev,szAppName,"rockey",6,"123456",6,SECURE_USER_ACCOUNT,phApp);
	if(rv)
	{
		PrintError("SKF_CreateApplication",rv,szAppList);
		return rv;
	}

	printf("Create Application %s succeed!\n",szAppName);
	if(szAppList)
	{
		free(szAppList);
		szAppList = NULL;
	}

	return SAR_OK;
}


ULONG RasKeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp)
{

	ULONG rv = SAR_OK,ulRetryCount =0;
	HCONTAINER hCon;
	char szContainer[64]={0};

	rv = SKF_VerifyPIN(hApp,USER_TYPE,"123456",&ulRetryCount);
	if(rv)
	{
		PrintError("SKF_VerifyPIN",rv);
		return rv;
	}

	memcpy(szContainer,"RSA_Container",13);

	rv = SKF_CreateContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_CreateContainer",rv);
		return rv;

	}

	RSAPUBLICKEYBLOB RsaPubKey;

	rv = SKF_GenRSAKeyPair(hCon,1024,&RsaPubKey);
	if(rv)
	{
		PrintError("SKF_GenRSAKeyPair",rv);
		return rv;
	}

	unsigned char pbData[1024]={0},pbDigest[32]={0},pbSignData[128]={0};
	ULONG ulDataLen = 1024,ulDigestLen = 32,ulSignDataLen = 128;

	ULONG i = 0;
	for(i =0;i<1024;i++)
	{
		pbData[i] = (unsigned char)((i*4+3)%256);
	}

	HANDLE hHash;

	rv = SKF_DigestInit(hDev,SGD_SHA1,NULL,NULL,0,&hHash);
	if(rv)
	{
		PrintError("SKF_DigestInit",rv);
		return rv;
	}

	rv = SKF_Digest(hHash,pbData,ulDataLen,pbDigest,&ulDigestLen);
	if(rv)
	{
		PrintError("SKF_Digest",rv);
		return rv;
	}

	printf("the Digest of the Data is :\n");
	for(i=0;i<ulDigestLen;i++)
	{
		printf("0x%02x ",pbDigest[i]);
	}

	printf("\n");

	rv = SKF_RSASignData(hCon,pbDigest,ulDigestLen,pbSignData,&ulSignDataLen);
	if(rv)
	{
		PrintError("SKF_RSASignData",rv);
		return rv;
	}

	printf("the signValue of the Data is :\n");
	for(i=0;i<ulSignDataLen;i++)
	{
		printf("0x%02x ",pbSignData[i]);
	}

	printf("\n");

	rv = SKF_RSAVerify(hDev,&RsaPubKey,pbDigest,ulDigestLen,pbSignData,ulSignDataLen);
	if(rv)
	{
		PrintError("SKF_RSAVerify",rv);
		return rv;
	}
	printf("verify SignValue is succeed!\n");

	return SAR_OK;

}

ULONG ImportRSAKeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp)
{

	ULONG rv;

	RSAPUBLICKEYBLOB pPubKey;
	unsigned char pbWrappedKey[128]={0},pbEncryptedData[2048]={0},pbData[2048]={0};
	ULONG ulWrappedKeyLen=256,ulDataLen=0,ulEncryptedDataLen=2048,ulPubKeyLen = 0;
	BLOCKCIPHERPARAM EncryptParam;
	int offset=0;

	char szConName[64]={0};
	HCONTAINER hCon;
	memcpy(szConName,"RSA_Container",13);

	rv = SKF_OpenContainer(hApp,szConName,&hCon);
	if(rv)
	{
		PrintError("SKF_OpenContainer",rv);
		return rv;
	}

    HANDLE hSessionKey;
	ulPubKeyLen = sizeof(pPubKey);

	rv = SKF_ExportPublicKey(hCon,TRUE,(unsigned char *)&pPubKey,&ulPubKeyLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ExportPublicKey",rv);
		return rv;
	}

	rv = SKF_RSAExportSessionKey (hCon,SGD_SM1_ECB,&pPubKey,pbWrappedKey,&ulWrappedKeyLen,&hSessionKey);
	if(rv != SAR_OK)
	{
		PrintError("SKF_RSAExportSessionKey",rv);
		return rv;
	}

	memcpy(pbData,"\x30\x82\x02\x5D\x02\x01\x00\x02\x81\x81\x00\xD8\x6D\x24\x88\x39\x79\x0B\x3F\xDF\x65\x7C\x19\x28\x06\x58\x2B\x7B\x78\xC1\xF4\x8B\x0B\x26\x57\x6A\xD0\x26\x4B\x5F\x0A\x3A\x10\x6C\x60\x27\x48\x26\x78\xF8\x7D\x52\x45\x36\xC0\x2A\xAA\xA9\xBC\xED\xD1\x5A\x5A\x2F\xBD\xEC\xFD\x66\x37\xBA\x95\xD7\x9A\x0A\xEE\xA4\x13\x7E\x74\xB5\x83\xE2\x4E\xE3\x40\x24\x88\xCA\x61\x09\x3B\x6B\x59\xEA\xB8\x0A\x05\x8D\xCF\x52\x49\x0D\x7A\x1E\xE3\x52\xDB\xD8\x64\x0A\x3E\x45\x25\xA9\x61\xA7\x9E\xC2\xD9\xEE\xA1\x88\xC7\x2F\x41\x86\x8C\xD8\x80\x08\x14\x9D\x88\x55\x67\xCC\x92\x81\xF5\x02\x03\x01\x00\x01\x02\x81\x81\x00\x94\x90\xF7\x8E\xFB\xC4\xF7\xCF\xF4\xCE\x79\x8D\xDB\x47\xDF\xA6\x99\xAF\x9F\x94\xFB\x0D\xC0\x58\x29\xDE\x91\x2B\x14\x26\xB5\x0D\x29\x18\x28\x5F\x02\xE9\xEF\xCA\x37\x7B\x83\xC6\x0E\x83\xF0\xD8\xDC\x77\xE6\x0A\x1A\xD3\xC9\xA7\x79\x4F\xB0\x29\xC4\x42\xDE\x55\x07\xDB\xB7\xB8\x39\x4C\x28\xF7\x74\x56\x12\x2C\x0F\x03\xCF\x48\x45\xCE\xCF\x59\xCE\x5D\x6D\x0F\x0F\xFB\xBE\xD1\x6C\x1B\x88\x2D\x5B\x2E\x0D\x4B\x3F\xE7\x29\x13\x4E\x77\xFD\x50\xD8\xBA\xF3\xCD\x35\x91\x81\x21\xE8\x14\xC4\x35\xD2\xB6\x24\xA8\xC3\x03\x5A\x81\x02\x41\x00\xEF\xF4\x9F\xEC\x35\x98\x5C\xC5\x4C\xE3\x9B\x2F\x26\x7A\x93\x21\xC8\xBF\x53\x21\x0D\xA1\x34\x91\xF5\x69\xE4\x00\x90\x9F\x80\x1E\x5B\x34\x96\x66\xB5\x1F\x80\x7B\x64\x7D\x84\x6E\xA1\xD3\x3C\xEB\xC1\x10\x2E\x4D\x32\xA0\x3F\xD5\x2C\x16\x35\x88\x67\x67\x5B\xC9\x02\x41\x00\xE6\xE5\xC3\x43\xDE\x1A\xFD\x4F\xB2\x76\xA1\x3C\xDC\xDF\x93\x01\xC6\x58\x47\xEB\xAC\x12\x11\x8F\x80\xE9\x00\x79\x78\x85\xAB\xC4\x69\x85\xCE\xB2\xF4\x80\xBF\x91\x40\x09\xCC\xF2\x9B\x32\xB1\xDF\xB3\xAB\x26\x4A\x4B\x21\x8F\xC8\xC5\x29\xCA\xA8\xCA\xBA\xF2\xCD\x02\x41\x00\x91\x94\x77\xA6\x26\x8A\x0E\xD6\xC1\x24\x61\xD5\x44\x62\x1F\x7B\xE2\xC0\x79\x1D\xD7\x98\x13\x3D\xEE\x87\xD5\x05\xA6\xB8\xAE\x51\x3C\x82\x76\x31\x4F\xF8\x11\xCA\x4B\\
\x18\x7F\xCD\x63\x2E\xB6\x8A\x4D\xF2\x94\x34\xCF\xDF\x3B\x7B\x08\xA9\x5C\xC7\x29\xFD\x22\x49\x02\x40\x61\xEE\xF0\x2C\x58\x07\x50\x8B\xBE\x21\x2C\xF0\x58\xAA\x87\x7A\xC8\x3A\xE7\x7E\x61\x44\x64\xA8\x5E\x3F\xF5\x90\x8F\xFA\xFA\x48\xDB\x8D\x02\x87\xCA\xC6\xD4\xF9\xF1\x94\x76\x96\x2C\x17\x8B\x74\x5B\x8B\x6B\x39\x35\xB6\xAD\x7A\xB5\x8D\xAD\x44\x7C\x80\x60\xBD\x02\x40\x7A\xE3\x7A\xD8\x86\xF9\x2A\x1A\x8A\xE0\xEA\xB5\xD3\x62\x8E\xA7\x58\x08\x6C\x4D\x6B\x30\x5E\xFF\x06\xAC\x09\x48\x69\x8B\xDC\x9E\x16\x35\x65\x1F\x18\x62\xD7\xBF\x21\x54\x77\x32\x2E\xAA\x3D\x89\x0C\xD2\xFA\x30\xA0\x77\xD9\xB5\xD4\x5B\xFB\x99\x41\x3E\x09\xA5",1248);
   ulDataLen = 1248;


	EncryptParam.IVLen = 0;
	EncryptParam.PaddingType = 1;
	rv = SKF_EncryptInit(hSessionKey,EncryptParam);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptInit",rv);
		return rv;
	}

	rv = SKF_Encrypt(hSessionKey,pbData,ulDataLen,pbEncryptedData,&ulEncryptedDataLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_Encrypt",rv);
		return rv;
	}	

	rv = SKF_ImportRSAKeyPair(hCon,SGD_SM1_ECB,pbWrappedKey,ulWrappedKeyLen,pbEncryptedData,ulEncryptedDataLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ImportRSAKeyPair",rv);
		return rv;
	}
	printf("Import RSAKeyPair Succeed!\n");

	return SAR_OK;

}

ULONG SM2KeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp)
{

	ULONG rv = SAR_OK,ulRetryCount =0;
	HCONTAINER hCon;
	char szContainer[64]={0};
	
	rv = SKF_VerifyPIN(hApp,USER_TYPE,"123456",&ulRetryCount);
	if(rv)
	{
		PrintError("SKF_VerifyPIN",rv);
		return rv;
	}
	
	memcpy(szContainer,"SM2_Container",13);
	
	rv = SKF_CreateContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_CreateContainer",rv);
		return rv;
		
	}
	
	ECCPUBLICKEYBLOB EccPubKey;
	
	rv = SKF_GenECCKeyPair(hCon,SGD_SM2_1,&EccPubKey);
	if(rv)
	{
		PrintError("SKF_GenECCKeyPair",rv);
		return rv;
	}
	
	unsigned char pbData[1024]={0},pbDigest[32]={0},pbSignData[128]={0};
	ULONG ulDataLen = 1024,ulDigestLen = 32,ulSignDataLen = 128;
	ULONG i =0;
	for(i =0;i<1024;i++)
	{
		pbData[i] = (unsigned char )((i*4+3)%256);
	}
	
	HANDLE hHash;
	unsigned char userId[32]={0};
	ULONG ulUserIdLen = 0;
	memcpy(userId,"heyalei",7);

    ulUserIdLen = 7;
	
	rv = SKF_DigestInit(hDev,SGD_SM3,&EccPubKey,userId,ulUserIdLen,&hHash);
	if(rv)
	{
		PrintError("SKF_DigestInit",rv);
		return rv;
	}
	
	rv = SKF_Digest(hHash,pbData,ulDataLen,pbDigest,&ulDigestLen);
	if(rv)
	{
		PrintError("SKF_Digest",rv);
		return rv;
	}
	
	printf("the Digest of the Data is :\n");
	for(i=0;i<ulDigestLen;i++)
	{
		printf("0x%02x ",pbDigest[i]);
	}
	
	printf("\n");

	ECCSIGNATUREBLOB EccSignBlob;
	
	rv = SKF_ECCSignData(hCon,pbDigest,ulDigestLen,&EccSignBlob);
	if(rv)
	{
		PrintError("SKF_ECCSignData",rv);
		return rv;
	}
	memcpy(pbSignData,EccSignBlob.r+32,32);
	memcpy(pbSignData+32,EccSignBlob.s+32,32);
	printf("the signValue of the Data is :\n");
	for(i=0;i<64;i++)
	{
		printf("0x%02x ",pbSignData[i]);
	}
	
	printf("\n");
	
	rv = SKF_ECCVerify(hDev,&EccPubKey,pbDigest,ulDigestLen,&EccSignBlob);
	if(rv)
	{
		PrintError("SKF_RSAVerify",rv);
		return rv;
	}
	printf("SM2 verify SignValue is succeed!\n");
	
	return SAR_OK;

}

ULONG ImportSM2KeyPair_Test(DEVHANDLE hDev,HAPPLICATION hApp)
{
	ULONG rv,rLen;
	ECCPUBLICKEYBLOB pEccSignKey;
	ULONG ulEccPubKeyLen = sizeof(ECCPUBLICKEYBLOB);
	ECCCIPHERBLOB  *pEccCipherBlob=NULL;
	HANDLE hSessionKey;

	PENVELOPEDKEYBLOB pEnvelopedKeyBlob;
	unsigned char pbWrappedKey[32]={0},pbTmpData[1024]={0},pbEncryptedData[1024]={0},pbData[1024]={0};
	ULONG ulWrappedKeyLen=32,ulTmpDataLen=1024,ulEncryptedDataLen=1024;
	BLOCKCIPHERPARAM EncryptParam;
	int offset=0;


// 	ECCPRIVATEKEYBLOB pEccPriBlb = { 256,{ \
// 		0x40,0x00,0x14,0x24,0x83,0x02,0x14,0x20,0x42,0x88,0x02,0x4A,0x10,0x14,0x80,0x00,0x02,0x1C,0x00,0x09,0x83,0x58,0x21,0xAC,0x80,0x00,0xA0,0x13,0x11,0x00,0xA8,0x59, \
// 		0x40,0x00,0x14,0x24,0x83,0x02,0x14,0x20,0x42,0x88,0x02,0x4A,0x10,0x14,0x80,0x00,0x02,0x1C,0x00,0x09,0x83,0x58,0x21,0xAC,0x80,0x00,0xA0,0x13,0x11,0x00,0xA8,0x59
// 	}};

	ECCPRIVATEKEYBLOB pEccPriBlb = { 256,{ \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x40,0x00,0x14,0x24,0x83,0x02,0x14,0x20,0x42,0x88,0x02,0x4A,0x10,0x14,0x80,0x00,\
		0x02,0x1C,0x00,0x09,0x83,0x58,0x21,0xAC,0x80,0x00,0xA0,0x13,0x11,0x00,0xA8,0x59
	}};
	
	ECCPUBLICKEYBLOB pEccPubBlob = {256,{ \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x26,0xEA,0x8A,0x39,0x30,0x20,0x8E,0xFD,0x91,0x32,0xF7,0x1C,0x51,0x0A,0xAB,0x57, \
		0x43,0x8B,0x3D,0xBC,0x27,0xD3,0x04,0xE7,0x98,0xEC,0xCA,0xF2,0xA0,0xEA,0x74,0xEB \
	}, \
	{ \
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
	0x75,0x00,0xD9,0xCF,0xF3,0x0E,0x63,0x10,0x15,0xC7,0x73,0x72,0x8E,0x8C,0x25,0x09, \
	0x38,0x0A,0x22,0xE1,0xE7,0x42,0xB6,0xAB,0xA0,0x9D,0xCF,0x85,0x7C,0x42,0xCC,0xEA \
	}};

	char szContainer[64]={0};
	HCONTAINER hCon;

	memcpy(szContainer,"SM2_Container",13);

	rv = SKF_OpenContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_OpenContainer",rv);
		return rv;
	}

	rv = SKF_ExportPublicKey(hCon,TRUE,(unsigned char *)&pEccSignKey,&ulEccPubKeyLen);
	if(rv)
	{
		PrintError("SKF_ExportPublicKey",rv);
		return rv;
	}


    pEccCipherBlob = (ECCCIPHERBLOB *)malloc(sizeof(ECCCIPHERBLOB)+16-1);
	pEccCipherBlob->CipherLen =16;
	rv = SKF_ECCExportSessionKey (hCon,SGD_SM1_ECB,&pEccSignKey,pEccCipherBlob,&hSessionKey);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ExportPublicKey",rv);
		return rv;
	}

	memcpy(pbTmpData,(char *)&pEccPriBlb.PrivateKey,pEccPriBlb.BitLen/4);
	ulTmpDataLen = pEccPriBlb.BitLen/4;

	EncryptParam.IVLen = 0;
	EncryptParam.PaddingType = 0;
	rv = SKF_EncryptInit(hSessionKey,EncryptParam);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptInit",rv);
		return rv;
	}

	rv = SKF_EncryptUpdate(hSessionKey,pbTmpData,ulTmpDataLen,pbEncryptedData,&ulEncryptedDataLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptUpdate",rv);
		return rv;
	}
	rv = SKF_EncryptFinal(hSessionKey,pbEncryptedData+ulEncryptedDataLen,&rLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptFinal",rv);
		return rv;
	}

	ulEncryptedDataLen += rLen;

	pEnvelopedKeyBlob = (PENVELOPEDKEYBLOB)malloc(sizeof(ENVELOPEDKEYBLOB)+16-1);
    if(pEccCipherBlob == NULL)
	{
		printf("申请内存失败!");
		return -1;

	}

	pEnvelopedKeyBlob->Version = 1;
	pEnvelopedKeyBlob->ulSymmAlgID = SGD_SM1_ECB;
	pEnvelopedKeyBlob->ulBits = 256;
	pEnvelopedKeyBlob->PubKey = pEccPubBlob;
	
	memset(pbEncryptedData,0x00,32);
	memcpy((char *)&(pEnvelopedKeyBlob->ECCCipherBlob),pEccCipherBlob,sizeof(ECCCIPHERBLOB)+16-1);
	memcpy((char *)&(pEnvelopedKeyBlob->cbEncryptedPriKey),&pbEncryptedData,ulEncryptedDataLen);


	rv = SKF_ImportECCKeyPair (hCon,pEnvelopedKeyBlob);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ImportECCKeyPair",rv);
		return rv;
	}
	if(pEnvelopedKeyBlob)
	{
		free(pEnvelopedKeyBlob);
	}
	if(pEccCipherBlob)
	{
		free(pEccCipherBlob);
	}

	printf("Import SM2 KeyPiar succeed!\n");

	return SAR_OK;
}


ULONG ImportSessionKey_Test(DEVHANDLE hDev,HAPPLICATION hApp)
{
	ULONG ulConType = 0,rv =0;
	unsigned char *pbBlob = NULL,*pCipherData = NULL;
	ULONG ulBlobLen = 0;
    HANDLE hSessionKey;

	char szContainer[64]={0};
	HCONTAINER hCon;

	
///使用固定的SM2容器  可以枚举枚举容器，获取容器类型
	memcpy(szContainer,"SM2_Container",13);	
	rv = SKF_OpenContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_OpenContainer",rv);
		return rv;
	}

	///因为是SM2，所以预先知道公钥大小，，可以调用两次SKF_ExportPublicKey，第一次获取长度
	pbBlob = (unsigned char *)malloc(sizeof(ECCPUBLICKEYBLOB));
	ulBlobLen = sizeof(ECCPUBLICKEYBLOB);


	/////注意，必须导出加密密钥对的公钥
	rv = SKF_ExportPublicKey(hCon,FALSE,pbBlob,&ulBlobLen);  
	if(rv)
	{	
		printf("SKF_ExportPublicKey failed,rv = 0x%0x",rv);
		if(pbBlob)
		{
			free(pbBlob);
			pbBlob = NULL;
		}
		return rv;		
	}

	ECCCIPHERBLOB *pEccCipher= NULL;
	pEccCipher = (ECCCIPHERBLOB *)malloc(sizeof(ECCCIPHERBLOB)+16-1);
	memset((char *)pEccCipher,0x00,sizeof(ECCCIPHERBLOB)+16-1);

	pEccCipher->CipherLen = 16;   ///必须设定
	
	rv = SKF_ECCExportSessionKey(hCon,SGD_SM1_ECB,(ECCPUBLICKEYBLOB *)pbBlob,pEccCipher,&hSessionKey);
	if(rv)
	{
		printf("SKF_ECCExportSessionKey failed,rv = 0x%0x",rv);
		if(pbBlob)
		{
			free(pbBlob);
			pbBlob = NULL;
		}
		if(pEccCipher)
		{
			free(pEccCipher);
			pEccCipher = NULL;
		}
		return rv;		
	}

	rv = SKF_ImportSessionKey(hCon,SGD_SM1_ECB,(unsigned char *)pEccCipher,sizeof(ECCCIPHERBLOB)+16-1,&hSessionKey);
	if(rv)
	{
		printf("SKF_ImportSessionKey failed,rv = 0x%0x",rv);
		if(pbBlob)
		{
			free(pbBlob);
			pbBlob = NULL;
		}
		if(pEccCipher)
		{
			free(pEccCipher);
			pEccCipher = NULL;
		}
		return rv;	
	}

	if(pbBlob)
		free(pbBlob);
	if(pEccCipher)
		free(pCipherData);

	printf("ImportSessionKey succeed!\n");
	return SAR_OK;


}



void PrintError(char *szFunName,ULONG dwErrorCode,char *Buf)
{

	printf("the Fun %s failed! the ErrorCode is 0x%0x\n",szFunName,dwErrorCode);
	if(Buf)
	{
		free(Buf);
		Buf = NULL;
	
	}
}

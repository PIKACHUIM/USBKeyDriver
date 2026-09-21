/*
[]=========================================================================[]

	Copyright(C)  Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	ImportSelfSignCert.cpp

DESC:
	This example code demonstrates how to create a self-sign certificate and
	then import it to Token.

NOTE:
	This example can not run on Windows98

[]=========================================================================[]
*/

#include "stdafx.h"

#define MY_ENCODING_TYPE	(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CERT_SUBJECT_NAME	"ePass Team @ Feitian Tech."
#define TEST_CSP_NAME		"FEITIAN ePassNG RSA Cryptographic Service Provider"
#define KEY_CA_CONTAINER	"CSPKeyTest"

//--------------------------------------------------------------------
//  This example uses the function HandleError, a simple error
//  handling function, to print an error message to the standard error 
//  (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void HandleError(char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of HandleError

//////////////////////////////////////////////////////////////////////////
void main(void)
{
	CERT_NAME_BLOB  SubjNameBlob;
	DWORD  cbNameEncoded = 0;
	BYTE*  pbNameEncoded = NULL;
	HCRYPTPROV  hCryptProv = 0;
	DWORD  cbPrivateKeyBlob = 0;
	BYTE*  pbPrivateKeyBlob = NULL;
	HCRYPTKEY hImpKey = 0;

	//////////////////////////////////////////////////////////////////////////
	// 1. to get CERT_NAME_BLOB
	//////////////////////////////////////////////////////////////////////////
	
	CERT_RDN_ATTR rgNameAttr[] = 
	{
		"2.5.4.3",                             // pszObjId 
		CERT_RDN_PRINTABLE_STRING,             // dwValueType
		strlen(CERT_SUBJECT_NAME),             // value.cbData
		(BYTE*)CERT_SUBJECT_NAME               // value.pbData
	};

	CERT_RDN rgRDN[] = 
	{
		1,                 // rgRDN[0].cRDNAttr
		&rgNameAttr[0]     // rgRDN[0].rgRDNAttr
	};

	CERT_NAME_INFO Name = 
	{
		1,                  // Name.cRDN
		rgRDN               // Name.rgRDN
	};

	if(CryptEncodeObject(
		MY_ENCODING_TYPE,     // Encoding type
		X509_NAME,            // Structure type
		&Name,                // Address of CERT_NAME_INFO structure
		NULL,                 // pbEncoded
		&cbNameEncoded))      // pbEncoded size
	{
		printf("The first call to CryptEncodeObject succeeded. \n");
	}
	else
	{
		HandleError("First call to CryptEncodeObject failed.\
		  \nA public/private key pair may not exit in the container. \n");
	}

	//Allocate memory for the encoded name.
	if(!(pbNameEncoded = (BYTE*)new BYTE[cbNameEncoded]))
		HandleError("pbNamencoded malloc operation failed.\n");

	//Call CryptEncodeObject to do the actual encoding of the name.
	if(CryptEncodeObject(
			MY_ENCODING_TYPE,    // Encoding type
			X509_NAME,           // Structure type
			&Name,               // Address of CERT_NAME_INFO structure
			pbNameEncoded,       // pbEncoded
			&cbNameEncoded))     // pbEncoded size
	{
		printf("The object is encoded. \n");
	}
	else
	{
		delete[] pbNameEncoded;
		HandleError("Second call to CryptEncodeObject failed.\n");
	}
	SubjNameBlob.cbData = cbNameEncoded;
	SubjNameBlob.pbData = pbNameEncoded;

	//////////////////////////////////////////////////////////////////////////
	// 2. to create self-sign certificate and get the private key blob
	//////////////////////////////////////////////////////////////////////////

	// Call CryptAcquireContext to initialize default CSP
	if(CryptAcquireContext(
		&hCryptProv,        // Address for handle to be returned.
		KEY_CA_CONTAINER,   // Use the current user's logon name.
		NULL,               // Use the default provider.
		PROV_RSA_FULL,      // Need to both encrypt and sign.
		NULL))              // No flags needed.
	{
		 printf("A cryptographic provider has been acquired. \n");
	}
	else if (GetLastError() == NTE_BAD_KEYSET)
	{
		if(CryptAcquireContext(
			&hCryptProv,        // Address for handle to be returned.
			KEY_CA_CONTAINER,   // Use the current user's logon name.
			NULL,               // Use the default provider.
			PROV_RSA_FULL,      // Need to both encrypt and sign.
			CRYPT_NEWKEYSET))   // new key set.
		{
			printf("A cryptographic provider has been acquired. \n");
		}
		else
		{
			delete[] pbNameEncoded;
			HandleError("CryptAcquireContext failed.");
		}
	}
	else
	{
		delete[] pbNameEncoded;
		HandleError("CryptAcquireContext failed.");
	}

	// Call CryptGenKey to generate key pair
	HCRYPTKEY hKey = 0;
	if (CryptGenKey(
		hCryptProv, 
		AT_SIGNATURE, 
		0x04000000 | CRYPT_EXPORTABLE,
		&hKey
		))
	{
		 printf("A key pair of AT_SIGNATURE has been generated \n");
	}
	else
	{
		delete[] pbNameEncoded;
		HandleError("CryptGenKey failed.");
	}

	// Create the self-sign certificate
	PCCERT_CONTEXT pCertCtx = CertCreateSelfSignCertificate(
		hCryptProv,
		&SubjNameBlob,
		0,
		NULL, 
		NULL,
		NULL,
		NULL,
		NULL);

	delete[] pbNameEncoded;
	if (pCertCtx == NULL)
	{
		HandleError("CertCreateSelfSignCertificate failed.");
	}
	else
	{
		printf("A self-sign certificate has been created!\n");
	}

	// to get private key blob
	if(CryptExportKey(
			  hKey,            // Provider handle
			  0,
			  PRIVATEKEYBLOB,
			  0,
			  NULL,                  // pbPublicKeyInfo
			  &cbPrivateKeyBlob))     // Size of PublicKeyInfo
	{
		 printf("The keyinfo structure is %d bytes.\n",cbPrivateKeyBlob);
	}
	else
	{
		HandleError("First call to CryptExportPublickKeyInfo failed.\
		   \nProbable cause: No key pair in the key container. \n");
	}

	
	// Allocate the necessary memory.
	if(pbPrivateKeyBlob = new BYTE[cbPrivateKeyBlob])
	{
		printf("Memory is allocated for the private key blob.\n");
	}
	else
	{
		HandleError("Memory allocation failed.");
	}
	//--------------------------------------------------------------------
	// Call CryptExportPublicKeyInfo to get pbPublicKeyInfo.

	if(CryptExportKey(
			  hKey,            // Provider handle
			  0,
			  PRIVATEKEYBLOB,
			  0,
			  pbPrivateKeyBlob,                  // pbPublicKeyInfo
			  &cbPrivateKeyBlob))     // Size of PublicKeyInfo
	{
		 printf("The keyinfo structure is %d bytes.\n",cbPrivateKeyBlob);
	}
	else
	{
		delete[] pbPrivateKeyBlob;
		HandleError("Second call to CryptExportKey failed.");
	}

	// Release the default CSP
	CryptReleaseContext(hCryptProv,0);

	//////////////////////////////////////////////////////////////////////////
	// 3. The following to demonstrate how to import key and certificate to Token
	//////////////////////////////////////////////////////////////////////////

	// To initialize the ePassNG CSP
	if(CryptAcquireContext(
		&hCryptProv,        
		KEY_CA_CONTAINER,
		TEST_CSP_NAME,		
		PROV_RSA_FULL,      
		CRYPT_NEWKEYSET))
	{
		 printf("ePassNG CSP has been acquired. \n");
	}
	else if (GetLastError() == NTE_EXISTS)
	{
		if(CryptAcquireContext(
			&hCryptProv,        
			KEY_CA_CONTAINER,
			TEST_CSP_NAME,		
			PROV_RSA_FULL,      
			0))
		{
			 printf("ePassNG CSP has been opened. \n");
		}
		else
		{
			HandleError("CryptAcquireContext failed.");
		}
	}
	else
	{
		HandleError("CryptAcquireContext failed.");
	}

	// To import private key 
	if(CryptImportKey(
		hCryptProv,
		pbPrivateKeyBlob, 
		cbPrivateKeyBlob,
		NULL,
		0,
		&hImpKey))
	{
		delete[] pbPrivateKeyBlob;
		printf("The private key has been imported !\n");
	}
	else
	{
		delete[] pbPrivateKeyBlob;
		HandleError("Failed to import private key!");
	}

	// To import certificate
	if(CryptSetKeyParam(
		hImpKey,
		KP_CERTIFICATE,
		pCertCtx->pbCertEncoded,
		0
		))
	{
		printf("The certificate has been imported!\n");
	}
	else
	{
		HandleError("Failed to import certificate!\n");
	}
	
	// Release ePassNG CSP
	CryptReleaseContext(hCryptProv, 0);
	printf("The private key and certificate have been imported!\n");

} // End of main


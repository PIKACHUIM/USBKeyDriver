/*
[]=========================================================================[]

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	SignVerifySign.cpp

DESC:
	Test signature and verify signature.
[]=========================================================================[]
*/

#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <wincrypt.h>

#define TEST_CSP_NAME	"FEITIAN ePassNG RSA Cryptographic Service Provider"
#define CONTAINER_NAME	"CSPKeyTest"

void MyHandleError(char *s);

void main(void)
{
	//-------------------------------------------------------------
	// Declare and initialize variables.
	
	HCRYPTPROV hProv;
	BYTE *pbBuffer= (BYTE *)"The data that is to be hashed and signed.";//data to be signed
	DWORD dwBufferLen = strlen((char *)pbBuffer)+1;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	BYTE *pbKeyBlob;			//pubkey of signer
	BYTE *pbSignature;			
	DWORD dwSigLen;
	DWORD dwBlobLen;
	
	//--------------------------------------------------------------------
	// get the CSP handle
	printf("The following phase of this program is signature.\n\n");
	if(CryptAcquireContext(
		&hProv, 
		NULL, 
		TEST_CSP_NAME,
		PROV_RSA_FULL, 
		0)) 
	{
		printf("CSP context acquired.\n");
	}
	else	//create if not exist
	{
		if(CryptAcquireContext(
			&hProv, 
			NULL, 
			TEST_CSP_NAME, 
			PROV_RSA_FULL, 
			CRYPT_NEWKEYSET)) 
		{
			printf("A new key container has been created.\n");
		}
		else
		{
			MyHandleError("Error during CryptAcquireContext.");
		}
	}

	//--------------------------------------------------------------------
	// get the sigkey from the container
	if(CryptGetUserKey(   
		hProv,    
		AT_SIGNATURE,    
		&hKey)) 
	{
		printf("The signature key has been acquired. \n");
	}
	else
	{
		if(GetLastError() == NTE_NO_KEY) //create it if not exist
		{
			if(CryptGenKey(
				hProv,			//CSP handle
				AT_SIGNATURE,	//type of signature key pair
				0,				//type of key,use default
				&hKey)) 		//returned value
			{
				printf("Created a signature key pair.\n");
			}
			else
			{
				MyHandleError("Error occurred creating a signature key.\n"); 
			}
			
		}
		else
		{
			MyHandleError("Error during CryptGetUserKey for signkey.");
		}
	}

	//--------------------------------------------------------------------
	// Export pubkey since the reciever need it to verify the signature
	if(CryptExportKey(   
		hKey,    
		NULL,    
		PUBLICKEYBLOB,
		0,    
		NULL, 
		&dwBlobLen))  //size
	{
		printf("Size of the BLOB for the public key determined. \n");
	}
	else
	{
		MyHandleError("Error computing BLOB length.");
	}

	//--------------------------------------------------------------------
	// buffer for pubkey
	if(pbKeyBlob = (BYTE*)malloc(dwBlobLen)) 
	{
		printf("Memory has been allocated for the BLOB. \n");
	}
	else
	{
		MyHandleError("Out of memory. \n");
	}

	//--------------------------------------------------------------------
	// export it
	if(CryptExportKey(   
		hKey, 
		NULL,    
		PUBLICKEYBLOB,    
		0,    
		pbKeyBlob,    
		&dwBlobLen))
	{
		printf("Contents have been written to the BLOB. \n");
	}
	else
	{
		MyHandleError("Error during CryptExportKey.");
	}

	//--------------------------------------------------------------------
	// create a hash object
	if(CryptCreateHash(
		hProv, 
		CALG_MD5, 
		0, 
		0, 
		&hHash)) 
	{
		printf("Hash object created. \n");
	}
	else
	{
		MyHandleError("Error during CryptCreateHash.");
	}

	//--------------------------------------------------------------------
	// hash the data
	if(CryptHashData(
		hHash, 
		pbBuffer, 
		dwBufferLen, 
		0)) 
	{
		printf("The data buffer has been hashed.\n");
	}
	else
	{
		MyHandleError("Error during CryptHashData.");
	}

	//--------------------------------------------------------------------
	// sign the hash

	dwSigLen= 0;
	if(CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		NULL, 
		0, 
		NULL, 
		&dwSigLen)) //size
	{
		printf("Signature length %d found.\n",dwSigLen);
	}
	else
	{
		MyHandleError("Error during CryptSignHash.");
	}

	//--------------------------------------------------------------------
	// buffer
	if(pbSignature = (BYTE *)malloc(dwSigLen))
	{
		printf("Memory allocated for the signature.\n");
	}
	else
	{
		MyHandleError("Out of memory.");
	}

	//--------------------------------------------------------------------
	// get the signature
	if(CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		NULL, 
		0, 
		pbSignature, //signature which should be send to the reciever togather with the signed data
		&dwSigLen)) 
	{
		printf("pbSignature is the hash signature.\n");
	}
	else
	{
		MyHandleError("Error during CryptSignHash.");
	}

	//--------------------------------------------------------------------
	// Destroy the hash object.
	if(hHash) 
		CryptDestroyHash(hHash);
	
	printf("The hash object has been destroyed.\n");
	printf("The signing phase of this program is completed.\n\n");
	
/********************************************************************************

  NOTE!!The following codes should be used on reciever's side.

*********************************************************************************/
	
	printf("The following phase of this program is verify signature.\n\n");
	
	// import the pubkey
	HCRYPTKEY hPubKey;
	if(CryptImportKey(
		hProv,
		pbKeyBlob,
		dwBlobLen,
		0,
		0,
		&hPubKey))
	{
		printf("The key has been imported.\n");
	}
	else
	{
		MyHandleError("Public key import failed.");
	}

	//--------------------------------------------------------------------
	// create hash object
	if(CryptCreateHash(
		hProv, 
		CALG_MD5, 
		0, 
		0, 
		&hHash)) 
	{
		printf("The hash object has been recreated. \n");
	}
	else
	{
		MyHandleError("Error during CryptCreateHash.");
	}

	//--------------------------------------------------------------------
	// hash the data
	if(CryptHashData(
		hHash, 
		pbBuffer, 
		dwBufferLen, 
		0)) 
	{
		printf("The new hash has been created.\n");
	}
	else
	{
		MyHandleError("Error during CryptHashData.");
	}

	//--------------------------------------------------------------------
	// verify the signature
	if(CryptVerifySignature(
		hHash, 
		pbSignature,
		dwSigLen, 
		hPubKey,
		NULL, 
		0)) 
	{
		printf("The signature has been verified.\n");
	}
	else
	{
		printf("Signature not validated!\n");
	}

	//--------------------------------------------------------------------
	// Free memory to be used to store signature.
	if(pbSignature)
		free(pbSignature);

	if(pbKeyBlob)
		free(pbKeyBlob);
	
	//--------------------------------------------------------------------
	// Destroy the hash object.
	if(hHash) 
		CryptDestroyHash(hHash);
	
	//--------------------------------------------------------------------
	// Release the provider handle.
	if(hProv) 
		CryptReleaseContext(hProv, 0);

	printf("\n\nPress any key to exit...\n");
	getch();
} //  End of main

//--------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the standard error 
//  (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError


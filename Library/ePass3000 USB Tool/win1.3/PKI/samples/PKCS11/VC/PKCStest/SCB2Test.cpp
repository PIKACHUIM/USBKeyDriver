// SCB2Test.cpp: implementation of the SCB2Test class.
//
//////////////////////////////////////////////////////////////////////

#include "SCB2Test.h"
#include "common.h"

#define DATA_SIZE	32
#define BLOCK_SIZE	20
#define DEC_BLOCK_SIZE	16

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

SCB2Test::SCB2Test(char* dll_file_path):CBaseAll(dll_file_path)
{
	m_hKey = 0;
}

SCB2Test::~SCB2Test()
{

}


void SCB2Test::Test()
{
	if(CKR_OK != BaseAllStart())
		return;
	GenerateKey();
	if(m_hKey == 0)
	{
		BaseAllEnd();
		return ;
	}
	crypt_Single();
	crypt_Update();
	BaseAllEnd();
}
void SCB2Test::GenerateKey()
{
	do{
		SHOW_INFO("Generate SCB2 key to test...");
		CK_OBJECT_CLASS oClass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_SCB2; 
		CK_BBOOL bTrue = true;
		CK_BBOOL bFalse = false;
		CK_ULONG ulLen = 16;
		CK_MECHANISM mechanism = {CKM_SCB2_KEY_GEN, NULL_PTR, 0};
		CK_ATTRIBUTE SCB2tem[] = {
			{CKA_CLASS, &oClass, sizeof(CK_OBJECT_CLASS)},
			{CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
			{CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
			{CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
			{CKA_ENCRYPT, &bTrue, sizeof(CK_BBOOL)},
			{CKA_DECRYPT, &bTrue, sizeof(CK_BBOOL)},
			{CKA_VALUE_LEN, &ulLen, sizeof(CK_ULONG)}, 
		};
		CK_ULONG ulCount = sizeof(SCB2tem)/sizeof(CK_ATTRIBUTE);
		//generate key:
		START_OP("generate SCB2 key...")
			CK_RV rv =  m_gToken->C_GenerateKey(hSession, &mechanism, SCB2tem, ulCount, &m_hKey); 
		CHECK_OP(rv)
	}while(0);
}
void SCB2Test::crypt_Single()
{
	const CK_ULONG DATA_LENGTH = 1024*3;
	CK_BYTE bIn[DATA_LENGTH] = {0}, bTemp[DATA_LENGTH] = {0}, bOut[DATA_LENGTH] = {0};
	CK_ULONG ulIn = 0, ulOut = 0, ulTemp = 0;
	CK_ULONG Mechanism[3] = {CKM_SCB2_CBC, CKM_SCB2_ECB, CKM_SCB2_CBC_PAD};
	CK_BYTE_PTR bHint[3] = {(CK_BYTE_PTR)"CKM_SCB2_CBC: ",\
							(CK_BYTE_PTR)"CKM_SCB2_ECB: ",
							(CK_BYTE_PTR)"CKM_SCB2_CBC_PAD: "};
	SHOW_INFO("\nSCB2: C_Encrypt/C_Decrypt: \n");
	do{
		for(int i=0;i<3;i++)
		{
			
			for (i != 2 ? ulIn = SCB2_BLOCK_LEN : ulIn = 0; ulIn < 32; i != 2 ? ulIn += SCB2_BLOCK_LEN : ++ulIn)
			{
				for(register CK_ULONG i0 = 0;i0<ulIn;i0++)
					bIn[i0] = (CK_BYTE)i0;
				
				
				SHOW_INFO("\n********************************\n");
				SHOW_INFO(bHint[i]);
				//ecnrypt init:
				CK_BYTE iv[16] = {'*','2','1','0','4','z','y','b','*','2','1','0','4','z','y','b'};
				CK_MECHANISM ckMechanism = {Mechanism[i], iv, 16};
				START_OP("Encrypting initialize.")  
				CK_RV rv =  m_gToken->C_EncryptInit(hSession, &ckMechanism, m_hKey); 
				CHECK_OP(rv)

				START_OP("Encrypt the message.")
				//Get the encrypted buffer's size:
				//{{{Here, I do not invoke "C_Encrypt" twice for I had declared bTemp with a size=1024.
				//If you do not declare the result's buffer previous,
				//you should invoke twice to get the buffer's size, such as:[Decrypt is similar]
				rv =  m_gToken->C_Encrypt(hSession, bIn, ulIn, NULL, &ulTemp);
				//}}}
				CheckRV("C_Encrypt[get buffer's size]", rv);
				//encrypt:
				rv =  m_gToken->C_Encrypt(hSession, bIn, ulIn, bTemp, &ulTemp);
				CheckRV("C_Encrypt", rv);
				CHECK_OP(rv);
				SHOW_INFO("Data encrypted: \n");
				ShowData(bTemp, ulTemp);

				START_OP("Decrypting initialize.");
				rv =  m_gToken->C_DecryptInit(hSession, &ckMechanism, m_hKey);
				CHECK_OP(rv);
				START_OP("Decrypt the message.");
				//Get buffer's size:
				rv =  m_gToken->C_Decrypt(hSession, bTemp, ulTemp, NULL, &ulOut);
				//Get decrypted data:
				rv =  m_gToken->C_Decrypt(hSession, bTemp, ulTemp, bOut, &ulOut);
				CHECK_OP(rv);
				SHOW_INFO("Data decrypted: \n");
				ShowData(bOut, ulOut);
				
				START_OP("Compare the original message and decrypted data: ");
				if(0 == memcmp(bIn, bOut, ulOut))
				{
					CHECK_OP(CKR_OK);
				}
				else
				{
					SHOW_INFO("....[FAILED]\n");
				}
			}
		}
	}while(0);

}

void SCB2Test::crypt_Update()
{
	const CK_ULONG DATA_LENGTH = 1024*3;
	CK_BYTE bIn[DATA_LENGTH] = {0}, bTemp[DATA_LENGTH] = {0}, bOut[DATA_LENGTH] = {0};
	CK_ULONG ulIn = 0, ulOut = 0, ulTemp = 0;
	CK_ULONG Mechanism[3] = {CKM_SCB2_CBC, CKM_SCB2_ECB, CKM_SCB2_CBC_PAD};
	CK_BYTE_PTR bHint[3] = {(CK_BYTE_PTR)"CKM_SCB2_CBC: ",\
									(CK_BYTE_PTR)"CKM_SCB2_ECB: ",\
									(CK_BYTE_PTR)"CKM_SCB2_CBC_PAD: "};
	SHOW_INFO("\n********************************\n");
	do{
		for(int i=0;i<3;i++)
		{
			for (i != 2 ? ulIn = SCB2_BLOCK_LEN : ulIn = 0; ulIn < 32; i != 2 ? ulIn += SCB2_BLOCK_LEN : ++ulIn)
			{			
				for(register CK_ULONG i0 = 0;i0<ulIn;i0++)
					bIn[i0] = (CK_BYTE)i0;

				SHOW_INFO("\n");
				SHOW_INFO("\nSCB2: C_EncryptUpdate/C_DecryptUpdate: \n");
				SHOW_INFO(bHint[i]);
				//ecnrypt init:
				CK_BYTE iv[16] = {'*','2','1','0','4','z','y','b','*','2','1','0','4','z','y','b'};
				CK_MECHANISM ckMechanism = {Mechanism[i], iv, sizeof(iv)};
				START_OP("Encrypting initialize.")  
					CK_RV rv =  m_gToken->C_EncryptInit(hSession, &ckMechanism, m_hKey); 
				CHECK_OP(rv)
				
				CK_ULONG ulEncrypted = 0;
				START_OP("Encrypt the message.");


				DWORD dwLoop = ulIn / BLOCK_SIZE;
				DWORD dwLeft = ulIn % BLOCK_SIZE;
				DWORD iii = 0;
				CK_BYTE_PTR pRetData = bTemp;
				for(iii = 0; iii < dwLoop ;++iii)
				{
					rv =  m_gToken->C_EncryptUpdate(hSession, bIn + BLOCK_SIZE * iii, BLOCK_SIZE, NULL, &ulTemp);//get buffer's size.
					rv =  m_gToken->C_EncryptUpdate(hSession, bIn + BLOCK_SIZE * iii, BLOCK_SIZE, pRetData, &ulTemp);
					pRetData += ulTemp;
					ulEncrypted+=ulTemp;
					CheckRV("C_Encrypt[inside loop]", rv);
				}
				if(0 != dwLeft)
				{
					rv =  m_gToken->C_EncryptUpdate(hSession, bIn + BLOCK_SIZE * iii, dwLeft, NULL, &ulTemp);//get buffer's size.
					rv =  m_gToken->C_EncryptUpdate(hSession, bIn + BLOCK_SIZE * iii, dwLeft, pRetData, &ulTemp);
					pRetData += ulTemp;
					ulEncrypted+=ulTemp;
					CheckRV("C_Encrypt[last block]", rv);
				}

	//			//invoked twice:
	//			const CK_ULONG ulEnc1stPice = 33;
	//			rv =  m_gToken->C_EncryptUpdate(hSession, bIn, ulEnc1stPice, NULL, &ulTemp);//get buffer's size.
	//			rv =  m_gToken->C_EncryptUpdate(hSession, bIn, ulEnc1stPice, bTemp, &ulTemp);
	//			//}}}
	//			CheckRV("C_Encrypt[get buffer's size]", rv);
	//			ulEncrypted+=ulTemp;
	//			ulTemp = 0;
	//			//encrypt:
	//			//invoked twice:
	//			rv =  m_gToken->C_EncryptUpdate(hSession,  &(bIn[ulEnc1stPice]), ulIn-ulEnc1stPice, NULL, &ulTemp);//get buffer's size.
	//			rv =  m_gToken->C_EncryptUpdate(hSession, &(bIn[ulEnc1stPice]), ulIn-ulEnc1stPice, &(bTemp[ulEncrypted]), &ulTemp);
	//			CheckRV("C_Encrypt", rv);
	//			CHECK_OP(rv);
	//			ulEncrypted+=ulTemp;
	//			ulTemp = 0;

				START_OP("C_EncryptFinal...");
				rv = m_gToken->C_EncryptFinal(hSession, NULL, &ulTemp);
				rv = m_gToken->C_EncryptFinal(hSession, pRetData, &ulTemp);
				CHECK_OP(rv);
				ulEncrypted+=ulTemp;
				ulTemp = 0;
				SHOW_INFO("Data encrypted: \n");
				ShowData(bTemp, ulEncrypted);

	//-------------------------------------------------------------------------//
				
				START_OP("Decrypting initialize.");
				CK_BYTE iv1[16] = {'*','2','1','0','4','z','y','b','*','2','1','0','4','z','y','b'};	
				CK_MECHANISM ckMechanism1 = {Mechanism[i], iv1, sizeof(iv1)};
				rv =  m_gToken->C_DecryptInit(hSession, &ckMechanism1, m_hKey);
				CHECK_OP(rv);
				START_OP("Decrypt the message.");

				dwLoop = ulEncrypted / DEC_BLOCK_SIZE;
	//			dwLeft = ulEncrypted % DEC_BLOCK_SIZE;

				iii = 0;
				pRetData = bOut;
				CK_ULONG ulDecrypt = 0;
				for(iii = 0; iii < dwLoop ;++iii)
				{
					rv =  m_gToken->C_DecryptUpdate(hSession, bTemp + DEC_BLOCK_SIZE * iii, DEC_BLOCK_SIZE, NULL, &ulTemp);//get buffer's size.
					rv =  m_gToken->C_DecryptUpdate(hSession, bTemp + DEC_BLOCK_SIZE * iii, DEC_BLOCK_SIZE, pRetData, &ulTemp);
					pRetData += ulTemp;
					ulDecrypt+=ulTemp;
					CheckRV("C_Decrypt[inside loop]", rv);
				}
	//			if(0 != dwLeft)
	//			{
	//				rv =  m_gToken->C_DecryptUpdate(hSession, bTemp + DEC_BLOCK_SIZE * iii, dwLeft, NULL, &ulTemp);//get buffer's size.
	//				rv =  m_gToken->C_DecryptUpdate(hSession, bTemp + DEC_BLOCK_SIZE * iii, dwLeft, pRetData, &ulTemp);
	//				pRetData += ulTemp;
	//				ulDecrypt+=ulTemp;
	//				CheckRV("C_Decrypt[last block]", rv);
	//			}
	//-------------------------------------------------------------------------//

	//			//Get buffer's size:
	//			CK_ULONG ulDecrypt = 0;
	//			const CK_ULONG ulDec1stPice = 11;
	//			rv =  m_gToken->C_DecryptUpdate(hSession, bTemp, ulDec1stPice, NULL, &ulOut);
	//			rv =  m_gToken->C_DecryptUpdate(hSession, bTemp, ulDec1stPice, bOut, &ulOut);
	//			ulDecrypt +=ulOut;
	//			ulOut = 0;
	//			//Get decrypted data:
	//			rv =  m_gToken->C_DecryptUpdate(hSession, &(bTemp[ulDec1stPice]), ulEncrypted-ulDec1stPice, NULL, &ulOut);
	//			rv =  m_gToken->C_DecryptUpdate(hSession, &(bTemp[ulDec1stPice]), ulEncrypted-ulDec1stPice, &(bOut[ulDecrypt]), &ulOut);
	//			CHECK_OP(rv);
	//			ulDecrypt +=ulOut;
	//			ulOut = 0;
				START_OP("C_DecryptFinale...");
	//			rv = m_gToken->C_DecryptFinal(hSession, &(bOut[ulDecrypt]), &ulOut);
				rv = m_gToken->C_DecryptFinal(hSession, NULL, &ulTemp);
				rv = m_gToken->C_DecryptFinal(hSession, pRetData, &ulTemp);
				CHECK_OP(rv);
				ulDecrypt += ulTemp;
				
				SHOW_INFO("Data decrypted: \n");
				ShowData(bOut, ulDecrypt);
				
				START_OP("Compare the original message and decrypted data: ");
				if(0 == memcmp(bIn, bOut, ulDecrypt))
				{
					CHECK_OP(CKR_OK);
				}
				else
				{
					SHOW_INFO("....[FAILED]\n");
				}
			}
		}
	}while(0);
}

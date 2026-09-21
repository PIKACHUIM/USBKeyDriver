// PKIInit.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "init_header.h"

typedef CK_RV (* C_GETFUNCTIONLISTPROC)(CK_FUNCTION_LIST_PTR_PTR); 
typedef CK_RV (* PRIINIT)(CK_SLOT_ID, INIT_TOKEN_PRARM_PTR); 
typedef CK_RV (* PKIINIT)(CK_SLOT_ID);
typedef CK_RV (* SetIsSupportSSF33)(CK_BBOOL);
typedef CK_RV (* SetIsSupportSCB2)(CK_BBOOL);

static SetIsSupportSSF33 pSetIsSupportSSF33;
static SetIsSupportSCB2  pSetIsSupportSCB2;
static C_GETFUNCTIONLISTPROC pC_GetFunctionList;
static PRIINIT pPriInit; 
static PKIINIT pPkiInit;
static CK_FUNCTION_LIST_PTR ePass = NULL; 

HINSTANCE m_hLibP11;
HINSTANCE m_hLibInit;


void ShowMainCmdMenu()
{
	printf("\n\nMain Menu:\n");
	printf("------------------------------------\n");
	printf("Press any key to init the token,or ESC to exit......\n");
	printf("\n");
	
}

unsigned long Do_Init()
{
	printf("Initialize...\n");
	CK_RV ck_rv = 0;
	CK_ULONG ulTokenCount = 0;
	CK_SLOT_ID_PTR pSlotID = NULL;

	
	INIT_TOKEN_PARAM initParam={0};
	

	CK_BBOOL IsSupportSSF33 = FALSE;
	CK_BBOOL IsSupportSCB2 = FALSE;
	
	
	ck_rv = ePass->C_GetSlotList(TRUE, NULL_PTR, &ulTokenCount);
	if(ck_rv != CKR_OK)
	{
		printf("C_GetSlotList 1 Error: %08x \n", ck_rv);
		return ck_rv;
	}
	
	if(ulTokenCount == 0)
	{
		printf("No Found Slot! \n");
		goto InitClean;
	}
	
	pSlotID = new CK_SLOT_ID[ulTokenCount*sizeof(CK_SLOT_ID)];
	ck_rv = ePass->C_GetSlotList(TRUE,pSlotID,&ulTokenCount);
	if(ck_rv != CKR_OK)
	{
		printf("C_GetSlotList 2 Error: %08x \n", ck_rv);
		
		goto InitClean;
	}


	char	szSSF33[10], szSCB2[10];
	/*
	if you sure your key support SSF33, 
	you must set the IsSupportSCB2 = TRUE.
	*/
	printf("Are you sure this key support SSF33?\nY/N:");
	scanf("%s", szSSF33);
	if( 0 == strcmp("Y", szSSF33) || 0 == strcmp("y", szSSF33))
		IsSupportSSF33 = TRUE;
	else if( 0 == strcmp("N", szSSF33) || 0 == strcmp("n", szSSF33))
		IsSupportSSF33 = FALSE;
	else
	{
		printf("You have input wrong choose about SSF33.");
		goto InitClean;
	}
	ck_rv = pSetIsSupportSSF33(IsSupportSSF33);
	if(ck_rv != CKR_OK)
	{
		printf("pSetIsSupportSSF33 Error: %08x", ck_rv);
		goto InitClean;
	}	
	/*
	if you sure your key support SCB2, 
	you must set the IsSupportSCB2 = TRUE.
	*/
	IsSupportSCB2 = TRUE;
	printf("Are you sure this key support SCB2?\nY/N:");
	scanf("%s", szSCB2);
	if( 0 == strcmp("Y", szSCB2) || 0 == strcmp("y", szSCB2))
		IsSupportSCB2 = TRUE;
	else if( 0 == strcmp("N", szSCB2) || 0 == strcmp("n", szSCB2))
		IsSupportSCB2 = FALSE;
	else
	{
		printf("You have input wrong choose about SCB2.");
		goto InitClean;
	}

	ck_rv = pSetIsSupportSCB2(IsSupportSCB2);
	if(ck_rv != CKR_OK)
	{
		printf("pSetIsSupportSCB2 Error: %08x", ck_rv);
		goto InitClean;
	}	

	initParam.InitType = 3;
	initParam.SoPinEC = 6;
	initParam.userPinEC = 6;
	if(IsSupportSCB2)
	{
		initParam.ulPrvSize = 15000;
		initParam.ulPubSize = 16000;
	}
	else
	{
		initParam.ulPrvSize = 16165;
		initParam.ulPubSize = 30000;
	}
	ck_rv = pPriInit(pSlotID[0],&initParam);
	if(ck_rv != CKR_OK)
	{
		printf("pPriInit Error: %08x \n", ck_rv);
		goto InitClean;
	}
	
	ck_rv = pPkiInit(pSlotID[0]);
	if(ck_rv != CKR_OK)
	{
		printf("pPkiInit Error: %08x \n", ck_rv);
		goto InitClean;
	}
	
	printf("Success!\n");
	
InitClean:

	if(pSlotID != NULL)
	{
		delete [] pSlotID;
		pSlotID = NULL;
	}
	return CKR_OK;	
}

int main(int argc, char* argv[])
{
	m_hLibP11 = LoadLibrary("ngp11v211.dll");
	if(!m_hLibP11)
	{
		printf("Load ngp11v211.dll Error! \n");
		return FALSE;
	}
	
	m_hLibInit = LoadLibrary("init_fteps3k_sc.dll");
	if(!m_hLibInit)
	{
		if(m_hLibP11)
			FreeLibrary(m_hLibP11);	

		printf("Load init_fteps3k_sc.dll Error! \n");
		return FALSE;
	}
	
	pC_GetFunctionList = (C_GETFUNCTIONLISTPROC)GetProcAddress(m_hLibP11,"C_GetFunctionList");
	pPriInit = (PRIINIT)GetProcAddress(m_hLibInit,"Init_DoPrvInit");
	pPkiInit = (PKIINIT)GetProcAddress(m_hLibInit,"Init_DoPKInit");
	pSetIsSupportSSF33 = (SetIsSupportSSF33)GetProcAddress(m_hLibInit,"Init_SetIsSupportSSF33");
 	pSetIsSupportSCB2 = (SetIsSupportSCB2)GetProcAddress(m_hLibInit,"Init_SetIsSupportSCB2");

	pC_GetFunctionList(&ePass);	
	
	//
	CK_RV ck_rv = ePass->C_Initialize(NULL_PTR);
	if(ck_rv != CKR_OK && ck_rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		if(m_hLibP11)
			FreeLibrary(m_hLibP11);	
		if(m_hLibInit)
			FreeLibrary(m_hLibInit);

		printf("C_Initialize Error: %08x \n", ck_rv);
		return FALSE;
	}
	while(true)
	{
		ShowMainCmdMenu();
		
		char ch = getch();
		if(0x1b == ch)
			break;//exit
		
		Do_Init();
	}

	ck_rv = ePass->C_Finalize(NULL_PTR);
	if(ck_rv != CKR_OK)
	{
		if(m_hLibP11)
			FreeLibrary(m_hLibP11);	
		if(m_hLibInit)
			FreeLibrary(m_hLibInit);

		printf("C_Finalize Error: %08x \n", ck_rv);
		return FALSE;
	}
	
	if(m_hLibP11)
		FreeLibrary(m_hLibP11);	
	if(m_hLibInit)
		FreeLibrary(m_hLibInit);
	
	return 0;
}


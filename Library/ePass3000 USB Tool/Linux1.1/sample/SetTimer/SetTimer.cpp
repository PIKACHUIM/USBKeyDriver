#include <iostream>
#include <dlfcn.h>
#include "../../include/cryptoki_ft.h"
#include "../../include/auxiliary.h"
#include "SetTimer.h"

using namespace std;

SetTimer::SetTimer()
{
	m_hPkiLib = NULL;
}
SetTimer::~SetTimer()
{
}

CK_RV SetTimer::Connect()
{
	CK_RV rv;
	rv = C_Initialize(NULL_PTR);
	if(CKR_OK != rv)
	{
		cout<<"Initialize PKCS#11 fault"<<endl;
		return rv;
	}
	CK_ULONG ulCount;
	rv = C_GetSlotList(TRUE, NULL_PTR, &ulCount);
	if(CKR_OK != rv)
	{
		cout<<"Get slot list fault"<<endl;
		return rv;
	}
	if(0 >= ulCount)
	{
		cout<<"Make sure you have inserted token"<<endl;
		return CKR_GENERAL_ERROR;
	}
	m_pSlotList = (CK_SLOT_ID_PTR)new CK_SLOT_ID[ulCount];
	if(NULL == m_pSlotList)
	{
		cout<<"Can't allocate enough memeroy"<<endl;
		return CKR_GENERAL_ERROR;
	}
	rv = C_GetSlotList(TRUE, m_pSlotList, &ulCount);
	if(CKR_OK != rv)
	{
		cout<<"Can't get slot list"<<endl;
		return rv;
	}else {
		cout<<"Connect OK!"<<endl;
		return rv;
	}

}
CK_RV SetTimer::Set(CK_BYTE minute)
{
	CK_RV rv;
	m_hPkiLib = dlopen("libepsng_p11.so", RTLD_NOW);
	if(NULL_PTR == m_hPkiLib)
	{
		cout<<"Can't load lib \"libepsng_p11.so.1\""<<endl;
		return CKR_GENERAL_ERROR;
	}
	EP_GetAuxFunctionList pE_GetAuxFunctionList = (EP_GetAuxFunctionList)dlsym(m_hPkiLib,"E_GetAuxFunctionList");
	if(NULL_PTR == pE_GetAuxFunctionList)
	{
		dlclose(m_hPkiLib);
		cout<<"Can't get function list"<<endl;
		return CKR_GENERAL_ERROR;
	}
	rv = pE_GetAuxFunctionList(&m_pAuxFunc);
	if(CKR_OK != rv)
	{
		dlclose(m_hPkiLib);
		cout<<"Can't get function list"<<endl;
		return CKR_GENERAL_ERROR;
	}
	rv = ((EP_SetLoginTimer)(m_pAuxFunc->pFunc[EP_SET_LOGIN_TIMER]))(m_pSlotList[0],minute);
	if(CKR_OK != rv)
	{
		dlclose(m_hPkiLib);
		cout<<"Set timer fault"<<endl;
		return rv;
	} else {
		cout<<"Set timer successfully"<<endl;
		dlclose(m_hPkiLib);
		return rv;
	}

}

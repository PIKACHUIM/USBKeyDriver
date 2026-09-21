/*
[]=========================================================================[]

	Copyright(C) 2005, Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	initdll.h

DESC:
	initialize dlls' interface	

REVISION:
	2005-04-11 [Skybird Le]
		Created.
[]=========================================================================[]
*/

#ifndef		__NG_INIT_HEADER
#define		__NG_INIT_HEADER 


//////////////////////////////////////////////////////////////////////////
// init dll's function typedef
//
typedef struct _INIT_TOKEN_PARAM_
{
	BYTE InitType;					// Must be 3
	char* strTokenName;				// token name, default "ePass Token"
	char* strSoPin;					// SO Pin, default "rockey"
	char* strUserPin;				// User Pin, default "1234"
	
	// the following two value have the top limit 15
	BYTE SoPinEC;					// max SO Pin error counter, 0x00 to default(5)
	BYTE userPinEC;					// max User Pin error counter, 0x00 to default(5)
	unsigned long ulPubSize;		// public storage size in bytes, 0x00 to default(24228)
	unsigned long ulPrvSize;		// private storage size in bytes, 0x00 to default(31744)
	unsigned long ulComputerID;		// computer id to initialize token (reserved)
} INIT_TOKEN_PARAM,CK_PTR INIT_TOKEN_PRARM_PTR;

#ifdef __cplusplus
extern "C"
{
#endif

CK_RV Init_SetIsSupportSSF33(CK_BBOOL bSupportSSF33);
CK_RV Init_SetIsSupportSCB2(CK_BBOOL bSupportSCB2);

CK_RV Init_DoPrvInit(CK_SLOT_ID slotId, INIT_TOKEN_PRARM_PTR pInitParam);
CK_RV Init_DoPKInit(CK_SLOT_ID slotID);

#ifdef __cplusplus
}
#endif
#endif // __NG_INIT_HEADER

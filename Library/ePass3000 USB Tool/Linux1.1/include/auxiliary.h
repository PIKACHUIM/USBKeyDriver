

#ifndef __AUXILIARY_H__
#define __AUXILIARY_H__
#include "notifymsg.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef
CK_DECLARE_FUNCTION_POINTER(CK_RV, EP_SetTokenLabel)
(	
	CK_SLOT_ID		slotID,		// ID of the token's slot
	CK_USER_TYPE	userType,	// the user type
	CK_CHAR_PTR		pPin,		// the user pin
	CK_ULONG		ulPinLen,	// length in bytes of the PIN
	CK_CHAR_PTR		pLabel		// 32-byte token label (blank padded)
);

struct AUX_PIN_INFO
{
	CK_BYTE bSOPinMaxRetries;
	CK_BYTE bSOPinCurCounter;
	CK_BYTE bUserPinMaxRetries;
	CK_BYTE bUserPinCurCounter;
	CK_FLAGS pinflags;
};
typedef AUX_PIN_INFO CK_PTR AUX_PIN_INFO_PTR;

typedef
CK_DECLARE_FUNCTION_POINTER(CK_RV, EP_GetPinInfo)
(
	CK_SLOT_ID			slotID,			// (IN) ID of the token's slot
	AUX_PIN_INFO_PTR	pPinInfo		// (OUT) pin info of this token
);

typedef
CK_DECLARE_FUNCTION_POINTER(CK_RV, EP_SetLoginTimer)
(
	CK_SLOT_ID		slotID,				// (IN) ID of the token's slot
	CK_BYTE		bucLogonTimeData	// (IN) Logon timer 
);

typedef
CK_DECLARE_FUNCTION_POINTER(CK_RV, EP_GetLoginTimer)
(
	CK_SLOT_ID		slotID,				// (IN) ID of the token's slot
	CK_BYTE_PTR		pbucLogonTimeData	// (OUT) Logon timer 
);

#define EP_SEND_DIRECT_CMD			0 
#define EP_SEND_EXT_CMD				1
#define EP_SET_TOKEN_LABEL			2
#define EP_INIT_TOKEN_PRIVATE			3

#define EP_GET_CONTAINER_LIST			4
#define EP_NEW_CONTAINER			5
#define EP_DELETE_CONTAINER			6
#define EP_GET_PIN_INFO				7
#define EP_GET_TOKEN_ID				8

#define EP_SET_NOTIFY_CALL_BACK			9
#define EP_SET_LOGIN_TIMER			10
#define EP_GET_LOGIN_TIMER			11

#define EP_FUNC_MAX_COUNT			20


struct AUX_FUNC_LIST
{
	CK_VERSION				version;  /* Auxiliary Version */
	CK_ULONG				ulFuncCount;
	void*					pFunc[EP_FUNC_MAX_COUNT];
};

typedef AUX_FUNC_LIST CK_PTR AUX_FUNC_LIST_PTR;
typedef AUX_FUNC_LIST_PTR CK_PTR AUX_FUNC_LIST_PTR_PTR;

CK_DECLARE_FUNCTION(CK_RV, E_GetAuxFunctionList)
(
	AUX_FUNC_LIST_PTR_PTR pAuxFunc
);

typedef
CK_DECLARE_FUNCTION_POINTER(CK_RV, EP_GetAuxFunctionList)
(
	AUX_FUNC_LIST_PTR_PTR pAuxFunc
);


#ifdef __cplusplus
}
#endif

#endif // __AUXILIARY_H__

// EOF



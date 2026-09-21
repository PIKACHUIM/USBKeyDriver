/*
[]=========================================================================[]

	Copyright(C) 2004-2005, Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	NGSetup.h

DESC:
	For NG Product Publish	

REVISION:
	2005-04-06 Created.
[]=========================================================================[]
*/
#ifndef __NG_SETUP_LIB_H__
#define __NG_SETUP_LIB_H__

/************************************************************************/
/* Return values only used by the instMW_IsHaveInstalled().
/************************************************************************/
#define ESA_NEVER_INSTALL					0
#define ESA_DEST_DVERSION_OLD				1
#define ESA_DEST_DVERSION_EQUAL				2
#define ESA_DEST_DVERSION_NEW				3

/************************************************************************/
/* Return values.
/************************************************************************/
#define ESA_SUCCESS								0x0000
#define ESA_ERR_FILE_NOT_FOUND					0x0001
#define ESA_ERR_COPY_FILES						0x0002
#define ESA_ERR_REG								0x0003
#define ESA_ERR_REG_CSP							0x0004
#define ESA_ERR_UNREG							0x0005
#define ESA_ERR_DEL_FILES						0x0006
#define ESA_ERR_DEL_DIR							0x0007
#define ESA_ERR_EXCTOR_FILES					0x0008
#define ESA_ERR_HOST_MEMORY						0x0009
#define ESA_ERR_REG_CARD_REG					0x000A
#define ESA_ERR_PRODUCT_ALD_INST				0x000B
#define ESA_ERR_NEEDREBOOT						0x000C

DWORD WINAPI instMW_Install(const char* szParam);
DWORD WINAPI instMW_Uninstall(const char* szParam);
DWORD WINAPI instMW_IsHaveInstalled(const char* szParam);
DWORD WINAPI instMW_IsNeedReboot(void);

#endif //__NG_SETUP_LIB_H__
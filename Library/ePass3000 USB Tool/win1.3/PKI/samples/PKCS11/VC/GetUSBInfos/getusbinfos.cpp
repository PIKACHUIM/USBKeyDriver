/*
[]=========================================================================[]
	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	getusbinfos.cpp

DESC:
[]=========================================================================[]
*/

#include "stdafx.h"
#include "getinfos.h"

//#ifdef TEST1k  
//	#define OPTION 1
//#elif defined(TEST2k)
//	#define OPTION 2
//#else 
	#define OPTION 3
//#endif

int main(int argc, char* argv[])
{
	CGetInfos inf(OPTION); 
	if(!inf.LoadLib())
		return 0;

	CK_SLOT_INFO slotInfo;
	unsigned long rv;

	CK_INFO cryptinfo;
	printf("Get Cryptoki information:\n");
	rv = inf.GetCryptokiInfos(&cryptinfo);
	inf.CheckRV(rv);
	inf.ShowCryptokiInfos(&cryptinfo);

	printf("Get Slot information:\n");
	rv = inf.GetSlotInfos(&slotInfo);
	inf.CheckRV(rv);
	printf("Get Token information:\n");
	CK_TOKEN_INFO tokeninfo;
	rv = inf.GetTokenInfos(&tokeninfo);
	inf.CheckRV(rv);
	::system("pause");

	return 0;
}






















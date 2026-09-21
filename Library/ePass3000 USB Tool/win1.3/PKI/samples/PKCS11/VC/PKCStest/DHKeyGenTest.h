/*
[]=========================================================================[]

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	dhkeygentest.h

DESC:
[]=========================================================================[]
*/


#if !defined _DHKEYGENTEST_H_
#define _DHKEYGENTEST_H_

#include "BaseAll.h"

class DHKeyGenTest:public CBaseAll
{
public:
	DHKeyGenTest(char* dll_file_path);
	virtual ~DHKeyGenTest();
	void DHKeyTest(void);

};

#endif // _DHKEYGENTEST_H_

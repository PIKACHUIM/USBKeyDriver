/*
[]=========================================================================[]

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	dsatest.h

DESC:
[]=========================================================================[]
*/

#ifndef _DSA_H_
#define _DSA_H_
#include "BaseAll.h"
class DSATest:public CBaseAll 
{
public:
	DSATest(char* dll_file_path);
	virtual ~DSATest();
	//{{{Test:
	void TestDSA(void);
	//}}}
private:
};

#endif //_DSA_H_
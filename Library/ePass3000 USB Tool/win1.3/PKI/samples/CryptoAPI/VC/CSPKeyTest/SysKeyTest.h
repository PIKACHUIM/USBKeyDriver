/*
[]=========================================================================[]

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	SysKeyTest.h

DESC:
	
[]=========================================================================[]
*/

#ifndef _SYSKEYTEST_H_
#define _SYSKEYTEST_H_

#define TEST_RC2_ALG	 CALG_RC2
#define TEST_RC4_ALG	 CALG_RC4
#define TEST_DES_ALG	 CALG_DES
#define TEST_SSF33_ALG	 CALG_SSF33
#define TEST_SCB2_ALG	 CALG_SCB2

class SysKeyTest  
{
public:
	SysKeyTest();
	virtual ~SysKeyTest();

	void TestKey(DWORD ulALG);
};

#endif // _SYSKEYTEST_H_

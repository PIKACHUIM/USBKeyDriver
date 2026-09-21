// SCB2Test.h: interface for the SCB2Test class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SCB2TEST_H__FFEFC1BE_164A_482C_A2A5_773E3681E54E__INCLUDED_)
#define AFX_SCB2TEST_H__FFEFC1BE_164A_482C_A2A5_773E3681E54E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "BaseAll.h"

class SCB2Test : public CBaseAll  
{
public:
	void Test(void);
	SCB2Test(char* dll_file_path);
	virtual ~SCB2Test();

	
private:
	void GenerateKey(void);
	void crypt_Single(void);
	void crypt_Update(void);
	CK_OBJECT_HANDLE m_hKey;
};

#endif // !defined(AFX_SCB2TEST_H__FFEFC1BE_164A_482C_A2A5_773E3681E54E__INCLUDED_)

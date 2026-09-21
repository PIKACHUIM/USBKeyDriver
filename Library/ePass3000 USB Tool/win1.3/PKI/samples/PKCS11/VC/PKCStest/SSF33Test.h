/********************************************************************
	Filename: 	destest.h
	Author:		Yubo
	
	Purpose:	interface for the Ssf33Test class.
*********************************************************************/
#if !defined _SSF33TEST_H_
#define _SSF33TEST_H_

#include "BaseAll.h"

class Ssf33Test : public CBaseAll  
{
public:
	Ssf33Test(char* dll_file_path);
	virtual ~Ssf33Test();
	void Test(void);
private:
	void GenerateKey(void);
	void crypt_Single(void);
	void crypt_Update(void);
	
private:
	CK_OBJECT_HANDLE m_hKey;
};

#endif // _SSF33TEST_H_

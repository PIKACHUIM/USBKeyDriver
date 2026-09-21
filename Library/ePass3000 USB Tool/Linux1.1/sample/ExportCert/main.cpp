#include <iostream>
#include <unistd.h>
#include "../../include/cryptoki_ft.h"
#include "exportcert.h"

using namespace std;

int main()
{
	CK_RV rv;
	rv = C_Initialize(NULL_PTR);
	if(CKR_OK != rv)
	{
		cout<<"Can not load ePassNG PKCS#11 lib"<<endl;
		return -1;
	}

	CExportcert test;
	rv = test.Init();
	if(CKR_OK != rv)
	{
		C_Finalize(NULL_PTR);
		return -1;
	}
	test.Export();

	C_Finalize(NULL_PTR);

	return 0;
}

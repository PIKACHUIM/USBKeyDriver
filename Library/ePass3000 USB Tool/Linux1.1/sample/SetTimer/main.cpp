#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include "../../include/cryptoki_ft.h"
#include "SetTimer.h"
using namespace std;

CK_RV CheckData(CK_BYTE_PTR data, char *sTemp)
{
	int i = 0;
	while(sTemp[i] != '\0')
	{
		if(!isdigit(sTemp[i]))
		{
			cout<<"1--240 only"<<endl;
			return CKR_CANCEL;
		}
		i++;
	}
	int aTemp = 0;
	aTemp = atoi(sTemp);
	if ((aTemp < 1) || (aTemp > 240))
	{
		cout<<"1--240 only"<<endl;
		return CKR_CANCEL;
	}
	*data = aTemp;
	return CKR_OK;
}

int main(int argc, char** argv)
{
	CK_BYTE minute;
	char cTemp[32];

	if(1 == argc)
	{
		cout<<"please input the minute(1--240)"<<endl;
		cin>>cTemp;
		if(!cin)
		{
			cout<<"empty input"<<endl;
			return CKR_CANCEL;
		}
	} 
	else 
	{
		memcpy(cTemp, argv[1], sizeof(argv[1]));
	}

	CK_RV rv;
	if(strlen(cTemp) > 3)
	{
		cout<<"too long"<<endl;
		exit(0);
	}
	rv = CheckData(&minute, cTemp);
	if(CKR_OK != rv)
	{
		return CKR_CANCEL;
	}
	SetTimer timer;
	rv = timer.Connect();
	if(CKR_OK != rv)
	{
		cout<<"Can't Connect to token"<<endl;
		return CKR_GENERAL_ERROR;
	}
	rv = timer.Set(minute);
	if(CKR_OK != rv)
	{
		cout<<"Set timer fault"<<endl;
		return CKR_GENERAL_ERROR;
	}
	else 
	{
		return CKR_OK;
	}
}

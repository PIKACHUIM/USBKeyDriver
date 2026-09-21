/*
[]=========================================================================[]

	Copyright(C)  Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	CSPKeyTest.cpp

DESC:
	ePassNG CSP Test, include key generation, encrypt and decrypt.
	Requirements: ePassNG run-time package installed.

[]=========================================================================[]
*/

#include "stdafx.h"

#include <csp\csp_ft.h>
#include "SysKeyTest.h"
#include "DeriveKeyTest.h"
#include "RSA.h"

#define TEST_EXIT					0
#define RC2TESTCHOISE				1
#define RC4TESTCHOISE				2
#define DESTESTCHOISE				3
#define SSF33TESTCHOISE				4
#define DERIVERC4KEYTESTCHOISE		5
#define DERIVEDESKEYTESTCHOISE		6
#define RSACHOISE					7
#define SCB2TESTCHOISE				8
#define GETPROVPARAM				9

void ShowTitle(void)
{
	cout << endl;
	cout << "===========================================================" << endl;
	cout << "Please choose the test item:" << endl;
	cout << "   1: RC2 Geneartion/Encryption/Decryption Test" << endl;
	cout << "   2: RC4 Geneartion/Encryption/Decryption Test" << endl;
	cout << "   3: DES Geneartion/Encryption/Decryption Test" << endl;
	cout << "   4: SSF33 Geneartion/Encryption/Decryption Test" << endl;
	cout << "   5: RC4 Derive Key Test" << endl;
	cout << "   6: DES Derive Key Test" << endl;
	cout << "   7: RSA Keypair Geneartion/Encryption/Decryption Test" << endl;
	cout << "   8: SCB2 Geneartion/Encryption/Decryption Test" <<endl << endl;
	cout << "   9: Show CSP Param" << endl << endl;
	cout << "   0: EXIT" << endl;
	cout << "===========================================================" << endl;
}

int main(void)
{
	for(;;)
	{
		ShowTitle();
		cout << "Input test item: ";
		char Choise[32] = {0};
		cin >> Choise;
		int iChoise = atoi(Choise);

		cout << endl << endl << "------------------------------------------------" << endl;

		switch(iChoise)
		{
		case RC2TESTCHOISE:
			{
				SysKeyTest test;
				cout << "RC2 test:" << endl;
				test.TestKey(TEST_RC2_ALG);
				cout << "RC2 test finish!" << endl;
			}
			break;

		case RC4TESTCHOISE:
			{
				SysKeyTest test;
				cout << "RC4 test:" << endl;
				test.TestKey(TEST_RC4_ALG);
				cout << "RC4 test finish!" << endl;
			}
			break;
		
		case DESTESTCHOISE:
			{
				SysKeyTest test;
				cout << "DES test:" << endl;
				test.TestKey(TEST_DES_ALG);
				cout << "Test DES key finish!" << endl;
			}
			break;
		case SSF33TESTCHOISE:
			{
				SysKeyTest test;
				cout << "SSF33 test:" << endl;
				test.TestKey(TEST_SSF33_ALG);
				cout << "Test SSF33 key finish!" << endl;
			}
			break;
		
		case DERIVERC4KEYTESTCHOISE:
			{
				DeriveKeyTest derkeytest;
				cout << "Derive RC4 test:" << endl;
				derkeytest.Testkey(TEST_RC4_ALG);
				cout << "Test Derive RC4 key finish!" << endl;
			}
			break;

		case DERIVEDESKEYTESTCHOISE:
			{
				DeriveKeyTest derkeytest;
				cout << "Derive DES test:" << endl;
				derkeytest.Testkey(TEST_DES_ALG);
				cout << "Test derive des key finish!" << endl;
			}
			break;

		case RSACHOISE:
			{
				CRSA rsaTest;
				cout << "RSA test:" << endl;
				rsaTest.TestRSA();
				cout << "Test RSA key pair finish!" << endl;
			}
			break;
		case SCB2TESTCHOISE:
			{
				SysKeyTest test;
				cout << "SCB2 test:" << endl;
				test.TestKey(TEST_SCB2_ALG);
				cout << "Test SCB2 key finish!" << endl;	
			}
			break;

		case GETPROVPARAM:
			cout << "Get CSP Parameters:" << endl;
			GetProvParam();
			cout << "Get CSP Parameters finish!" << endl;
			break;

		case TEST_EXIT:
			//cout << "Press any key to exit..." << endl;
			return 0;
		}

		cout << endl;
	}

	return 0;
}

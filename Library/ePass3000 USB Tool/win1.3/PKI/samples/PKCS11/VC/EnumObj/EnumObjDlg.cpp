// EnumObjDlg.cpp : implementation file
//

#include "stdafx.h"
#include "EnumObj.h"
#include "EnumObjDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#include "DlgUserPIN.h"

#define NEWLINE "\r\n"
/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

//////////////////////////////////////////////////////////////////////////
//byte to string according with special format
static CString nByteToStr(DWORD dwSize, void* pData, DWORD dwByte, DWORD dwSplit);

CString nByteToStr(DWORD dwSize, void* pData, DWORD dwByte, DWORD dwSplit)
{
	BYTE* pBuf = (BYTE*)pData; // local pointer to a BYTE in the BYTE array.
	
	CString strRet("");	
	DWORD nLine = 0;	
	DWORD dwLines = 0;
	DWORD dwRest = 0;
	bool bNeedSplit = true;
	char szTemp[20] = {0, };
	
	DWORD dwBlock = 0;	
	if(0 == dwSplit)
	{
		dwSplit = dwSize;
		bNeedSplit = false;
	}
	
	dwRest = dwSize % dwSplit;
	dwLines = dwSize / dwSplit;
	
	DWORD i, j, k, m;
	for(i = 0; i < dwLines; i++)
	{
		DWORD dwRestTemp = dwSplit % dwByte;
		DWORD dwByteBlock = dwSplit / dwByte;
		
		for(j = 0; j < dwByteBlock; j++)
		{
			for(k = 0; k < dwByte; k++)
			{
				wsprintf(szTemp, "%02X", pBuf[i * dwSplit + j * dwByte + k]);
				strRet += szTemp;
			}
			strRet += " ";
		}
		if(dwRestTemp)
		{
			for(m = 0; m < dwRestTemp; m++)
			{
				wsprintf(
					szTemp, "%02X",
					pBuf[i * dwSplit + j * dwByte + k - 3 + dwRestTemp]);
				strRet += szTemp;
			}
		}
		if(bNeedSplit)
			strRet += "\r\n";
	}
	
	if(dwRest)
	{
		DWORD dwRestTemp = dwRest % dwByte;
		DWORD dwByteBlock = dwRest / dwByte;
		for(j = 0; j < dwByteBlock; j++)
		{
			for(k = 0; k < dwByte; k++)
			{
				wsprintf(szTemp, "%02X", pBuf[dwSize - dwRest + k+ j * dwByte]);
				strRet += szTemp;
			}
			strRet += " ";
		}
		if(dwRestTemp)
		{
			for(m = 0; m < dwRestTemp; m++)
			{
				wsprintf(
					szTemp, "%02X",
					pBuf[dwSize - dwRest + k - 1 + dwRestTemp]);
				strRet += szTemp;
			}
		}
		if(bNeedSplit)
			strRet += "\r\n";
	}
	
	
	return strRet;
}  // End of ByteToStr


class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CEnumObjDlg dialog

CEnumObjDlg::CEnumObjDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CEnumObjDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CEnumObjDlg)
	m_strInfo = _T("");
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	
	m_pSlotList = NULL_PTR;
	m_pApplication = new char[255];
	ZeroMemory(m_pApplication, 255);
	lstrcpy((char*)m_pApplication, "Enum Object App");
	m_hSession = NULL_PTR;
}

CEnumObjDlg::~CEnumObjDlg()
{
	if(m_hSession)
	{
		C_CloseSession(m_hSession);
		m_hSession = NULL_PTR;
	}
	delete[] m_pApplication;
	if(m_pSlotList)
	{
		delete[] m_pSlotList;
		m_pSlotList = NULL_PTR;
	}

}


void CEnumObjDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CEnumObjDlg)
	DDX_Control(pDX, IDC_BTN_SECRET, m_btnSecret);
	DDX_Control(pDX, IDC_BTN_PUBLIC, m_btnPublic);
	DDX_Control(pDX, IDC_BTN_PRIVATE, m_btnPrivate);
	DDX_Control(pDX, IDC_BTN_DATA, m_btnData);
	DDX_Control(pDX, IDC_BTN_LOGIN, m_btnLogin);
	DDX_Control(pDX, IDC_BTN_ENUM, m_btnEnum);
	DDX_Control(pDX, IDC_BTN_CONNECT, m_btnConnect);
	DDX_Control(pDX, IDC_INFO, m_edtInfo);
	DDX_Text(pDX, IDC_INFO, m_strInfo);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CEnumObjDlg, CDialog)
	//{{AFX_MSG_MAP(CEnumObjDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_CONNECT, OnBtnConnect)
	ON_BN_CLICKED(IDC_BTN_CLEARINFO, OnBtnClearinfo)
	ON_BN_CLICKED(IDC_BTN_ENUM, OnBtnEnum)
	ON_BN_CLICKED(IDC_BTN_LOGIN, OnBtnLogin)
	ON_BN_CLICKED(IDC_BTN_DATA, OnBtnData)
	ON_BN_CLICKED(IDC_BTN_PUBLIC, OnBtnPublic)
	ON_BN_CLICKED(IDC_BTN_PRIVATE, OnBtnPrivate)
	ON_BN_CLICKED(IDC_BTN_SECRET, OnBtnSecret)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CEnumObjDlg message handlers

BOOL CEnumObjDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// TODO: Add extra initialization here	
	ShowMsg("You must first connect with Token!"NEWLINE);
	m_btnLogin.EnableWindow(FALSE);
	m_btnEnum.EnableWindow(FALSE);
	m_btnData.EnableWindow(FALSE);
	m_btnPublic.EnableWindow(FALSE);
	m_btnPrivate.EnableWindow(FALSE);
	m_btnSecret.EnableWindow(FALSE);

	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CEnumObjDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CEnumObjDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CEnumObjDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CEnumObjDlg::OnBtnConnect() 
{
	// TODO: Add your control notification handler code here
	if(m_hSession)
		return;
	
	::SetCursor(::LoadCursor(NULL, IDC_WAIT));
	
	StartOP();
	
	CK_RV rv;
	CK_ULONG ulCount = 0;
	rv = C_GetSlotList(TRUE, NULL_PTR, &ulCount);
	if(CKR_OK != rv )
	{
		ShowErr(NEWLINE"Can't Acquire the Information of Token,Error Code 0x%08X."NEWLINE, rv);
		return;
	}
	if(0 >= ulCount)
	{
		ShowMsg(NEWLINE"Can't Connect to Token,Make Sure You have inserted USB Token."NEWLINE);
		return;
	}
	
	m_pSlotList = (CK_SLOT_ID_PTR)new CK_SLOT_ID[ulCount];
	if (! m_pSlotList) 
	{
		ShowMsg(NEWLINE"Can't allocate enough memory!"NEWLINE);
		return;
	}
	
	rv = C_GetSlotList(TRUE, m_pSlotList, &ulCount);
	if(CKR_OK != rv )
	{
		ShowErr(NEWLINE"Can't Acquire the Information of Token,Error Code 0x%08X."NEWLINE, rv);
		return;
	}
	if(0 >= ulCount)
	{
		ShowMsg(NEWLINE"Can't Connect to Token,Make Sure You have inserted Token."NEWLINE);
		return;
	}
	
	rv = C_OpenSession(
		m_pSlotList[0],  CKF_RW_SESSION | CKF_SERIAL_SESSION,
		&m_pApplication, NULL_PTR, &m_hSession);
	if(CKR_OK != rv )
	{
		ShowErr(NEWLINE"Can't Connect to Token,Error Code 0x%08X."NEWLINE, rv);
		delete[] m_pSlotList;
		m_pSlotList = NULL_PTR;
	}
	else
	{
		ShowMsg(NEWLINE"Connect to token successfully!"NEWLINE);
		m_btnConnect.EnableWindow(FALSE);
		ShowMsg(NEWLINE"Now You can login as a User"NEWLINE);
		m_btnLogin.EnableWindow(TRUE);

	}
	
}

void CEnumObjDlg::ShowMsg(CString strInfo)
{
	m_strInfo += strInfo;
	UpdateData(FALSE);
	
	int nLastLine = m_edtInfo.GetLineCount();// GetFirstVisibleLine();
	
	if (nLastLine > 0)
	{
		m_edtInfo.LineScroll(nLastLine, 0);
	}
}

void CEnumObjDlg::StartOP()
{
	ShowMsg(NEWLINE"================================================");
}

void CEnumObjDlg::ShowErr(CString strInfo, CK_RV rv)
{
	CString strTemp("");
	strTemp.Format(strInfo.GetBuffer(strInfo.GetLength()), rv);
	ShowMsg(strTemp);
}

void CEnumObjDlg::OnBtnClearinfo() 
{
	// TODO: Add your control notification handler code here
	m_strInfo = "";
	UpdateData(FALSE);
}

void CEnumObjDlg::OnBtnEnum() 
{
	
	CK_OBJECT_CLASS dataClass = CKO_CERTIFICATE;
	BOOL IsToken=true;
	CK_ATTRIBUTE pTempl[] = 
	{
		{CKA_CLASS, &dataClass, sizeof(CKO_CERTIFICATE)},
		{CKA_TOKEN, &IsToken, sizeof(true)}
	};

	
	C_FindObjectsInit(m_hSession, pTempl, 2);
	
	CK_OBJECT_HANDLE hCKObj;
	CK_ULONG ulRetCount = 0;
	CK_RV ckrv = 0;
	int numObj=0;//object numbers
	do
	{
		ckrv = C_FindObjects(m_hSession, &hCKObj, 1, &ulRetCount);
		if(CKR_OK != ckrv)
		{
			break;	
		}
		if(1 != ulRetCount)
			break;
		
		CK_ATTRIBUTE pAttrTemp[] = 
		{
			{CKA_CLASS, NULL, 0},
			{CKA_CERTIFICATE_TYPE,NULL,0},
			{CKA_LABEL, NULL, 0},
			{CKA_SUBJECT,NULL,0},
			{CKA_ID,NULL,0},
			{CKA_VALUE,NULL,0}
		};
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 6);
		if(ckrv != CKR_OK)
		{
			break;
		}
		
		pAttrTemp[0].pValue = new char[pAttrTemp[0].ulValueLen];
		pAttrTemp[1].pValue = new char[pAttrTemp[1].ulValueLen];
		pAttrTemp[2].pValue = new char[pAttrTemp[2].ulValueLen+1];
		pAttrTemp[3].pValue = new char[pAttrTemp[3].ulValueLen+1];
		pAttrTemp[4].pValue = new char[pAttrTemp[4].ulValueLen+1];
		pAttrTemp[5].pValue = new char[pAttrTemp[5].ulValueLen ];
		
		ZeroMemory(pAttrTemp[0].pValue, pAttrTemp[0].ulValueLen);
		ZeroMemory(pAttrTemp[1].pValue, pAttrTemp[1].ulValueLen);
		ZeroMemory(pAttrTemp[2].pValue, pAttrTemp[2].ulValueLen+1);	
		ZeroMemory(pAttrTemp[3].pValue, pAttrTemp[3].ulValueLen+1);
		ZeroMemory(pAttrTemp[4].pValue, pAttrTemp[4].ulValueLen+1);
		ZeroMemory(pAttrTemp[5].pValue, pAttrTemp[5].ulValueLen);
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 6);
		if(ckrv != CKR_OK)
		{
			delete[] pAttrTemp[0].pValue;
			delete[] pAttrTemp[1].pValue;
			delete[] pAttrTemp[2].pValue;
			delete[] pAttrTemp[3].pValue;
			delete[] pAttrTemp[4].pValue;
			delete[] pAttrTemp[5].pValue;
			break;
		}

		numObj++;
		CString strvale = (char*)pAttrTemp[2].pValue;
		
		CString strsubject;
		CERT_NAME_BLOB  SubName;
		SubName.cbData=pAttrTemp[3].ulValueLen;
		SubName.pbData=(BYTE*)pAttrTemp[3].pValue;

		DWORD dwStrDetailType =
			CERT_NAME_STR_NO_QUOTING_FLAG | 
			CERT_NAME_STR_REVERSE_FLAG |
			CERT_SIMPLE_NAME_STR |
			CERT_OID_NAME_STR |
			CERT_NAME_STR_CRLF_FLAG
			;

		DWORD dwName = 0;
		dwName = CertNameToStr(
			MY_ENCODING_TYPE,
			&SubName,
			dwStrDetailType,
			NULL,
			0);
		
		if (0 == dwName)
		{
			AfxMessageBox("error get Subject Name length");
			return;
		}
		
		char* pszTemp = NULL;
		if(!(pszTemp = new char[dwName]))
		{
			AfxMessageBox("malloc memory  for subject name failed");
			return;
		}
		
		//--------------------------------------------------------------------
		//       Call the function again to get the string 
		dwName = CertNameToStr(
			MY_ENCODING_TYPE,
			&SubName,
			dwStrDetailType,
			pszTemp,
			dwName);
		
		//--------------------------------------------------------------------
		//      If the function succeeded, it returns the 
		//      number of bytes copied to the pszName buffer.
		if (1 < dwName)
		{
			strsubject = pszTemp;
		}
		delete[] pszTemp;

		//CString strckaid=(char*)pAttrTemp[4].pValue;
		
		ShowMsg(NEWLINE);
		StartOP();
		ShowMsg(NEWLINE"Begin this Object's Output:"NEWLINE);
		ShowMsg("The Attribute CKA_CLASS of this Obj is:: CKO_CERTIFICATE"NEWLINE);
		
		if(*(int*)pAttrTemp[1].pValue==CKC_X_509)
		{
		ShowMsg("The Attribute CKA_CERTIFICATE_TYPE is: CKC_X_509"NEWLINE);
		}
		else 
			if(*(int*)pAttrTemp[1].pValue==CKC_X_509_ATTR_CERT)
			{
				ShowMsg("CKA_CERTIFICATE_TYPE is CKC_X_509_ATTR_CERT"NEWLINE);
			}
		ShowMsg("The Attribute CKA_LABEL of this Obj is: ");
		ShowMsg(strvale);
		ShowMsg(NEWLINE"The Attribute CKA_SUBJECT of this Obj is: ");
		ShowMsg(strsubject);
		ShowMsg(NEWLINE"The Attribute CKA_ID of this Obj is: "NEWLINE);
		//ShowMsg(strckaid);
		ShowMsg(nByteToStr(pAttrTemp[4].ulValueLen, pAttrTemp[4].pValue, 1, 16));
		ShowMsg(NEWLINE"The Content of this Obj(CKA_VALUE) is:"NEWLINE);
		ShowMsg(nByteToStr(pAttrTemp[5].ulValueLen, pAttrTemp[5].pValue, 1, 16));
		ShowMsg(NEWLINE"Finish Output Obj"NEWLINE);
		
		
		delete[] pAttrTemp[0].pValue;
		delete[] pAttrTemp[1].pValue;
		delete[] pAttrTemp[2].pValue;
		delete[] pAttrTemp[3].pValue;
		delete[] pAttrTemp[4].pValue;
		delete[] pAttrTemp[5].pValue;
		
	}while(true);
	if(numObj==0)
	{
		StartOP();
		ShowMsg(NEWLINE"Can't find X.509 Certificate Obj"NEWLINE);
	}
	else
	{
		StartOP();
		CHAR strNumObj[4];
		wsprintf(strNumObj,"%d",numObj);
		ShowMsg(NEWLINE"Find ");
		ShowMsg(strNumObj);
		ShowMsg(" X.509 Certificate Obj"NEWLINE);
	}
}

void CEnumObjDlg::OnBtnLogin() 
{
	// TODO: Add your control notification handler code here
	StartOP();
	
	DlgUserPIN* dlgUserPIN = new DlgUserPIN;
	dlgUserPIN->DoModal();
	delete dlgUserPIN;
	if("" == g_strUserPIN)
	{
		ShowMsg(NEWLINE"Before Enum Obj ,You Must input user pin!"NEWLINE);
		return;
	}
	
	CK_ULONG ulPIN = g_strUserPIN.GetLength();
	CK_BYTE_PTR pPIN = (CK_BYTE_PTR)g_strUserPIN.GetBuffer(ulPIN);
	
	::SetCursor(::LoadCursor(NULL, IDC_WAIT));
	CK_RV rv;
	rv = C_Login(m_hSession, CKU_USER, pPIN, ulPIN);
	if(CKR_OK != rv)
	{
		ShowErr(NEWLINE"Can't use your pin login to Token,Error Code 0x%08X."NEWLINE, rv);
		if(rv==CKR_USER_ALREADY_LOGGED_IN)
			ShowErr(NEWLINE"you have logged in Token!",NULL);
		return;
	}
	else
		ShowMsg(NEWLINE"Login to Token successfully!"NEWLINE);
		m_btnEnum.EnableWindow(TRUE);
		m_btnData.EnableWindow(TRUE);
		m_btnPublic.EnableWindow(TRUE);
		m_btnPrivate.EnableWindow(TRUE);
		m_btnSecret.EnableWindow(TRUE);
	
}

void CEnumObjDlg::OnBtnData() 
{
	// TODO: Add your control notification handler code here
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	BOOL IsToken=true;
	CK_ATTRIBUTE pTempl[] = 
	{
		{CKA_CLASS, &dataClass, sizeof(CKO_DATA)},
		{CKA_TOKEN, &IsToken, sizeof(true)}
	};
	
	C_FindObjectsInit(m_hSession, pTempl, 2);
	
	CK_OBJECT_HANDLE hCKObj;
	CK_ULONG ulRetCount = 0;
	CK_RV ckrv = 0;

	int numObj=0;
	do
	{
		ckrv = C_FindObjects(m_hSession, &hCKObj, 1, &ulRetCount);
		if(CKR_OK != ckrv)
		{
			break;	
		}
		if(1 != ulRetCount)
			break;
		
		CK_ATTRIBUTE pAttrTemp[] = 
		{
			{CKA_CLASS, NULL, 0},
			{CKA_LABEL, NULL, 0},
			{CKA_APPLICATION, NULL, 0},
			{CKA_VALUE, NULL,0},
		};
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 4);
		if(ckrv != CKR_OK)
		{
			break;
		}
		
		pAttrTemp[0].pValue = new char[pAttrTemp[0].ulValueLen];
		pAttrTemp[1].pValue = new char[pAttrTemp[1].ulValueLen + 1];
		pAttrTemp[2].pValue = new char[pAttrTemp[2].ulValueLen + 1];
		pAttrTemp[3].pValue = new char[pAttrTemp[3].ulValueLen];
		ZeroMemory(pAttrTemp[0].pValue, pAttrTemp[0].ulValueLen);
		ZeroMemory(pAttrTemp[1].pValue, pAttrTemp[1].ulValueLen + 1);
		ZeroMemory(pAttrTemp[2].pValue, pAttrTemp[2].ulValueLen + 1);
		ZeroMemory(pAttrTemp[3].pValue, pAttrTemp[3].ulValueLen );
		

		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 4);
		if(ckrv != CKR_OK)
		{
			delete[] pAttrTemp[0].pValue;
			delete[] pAttrTemp[1].pValue;
			delete[] pAttrTemp[2].pValue;
			delete[] pAttrTemp[3].pValue;
			break;
		}
		numObj++;		
		int nClassTemp = *((int*)pAttrTemp[0].pValue);
		CString strvale = (char*)pAttrTemp[1].pValue;
		CString strApp= (char*)pAttrTemp[2].pValue;

		ShowMsg(NEWLINE);
		StartOP();
		ShowMsg(NEWLINE"Begin this Object's Output:"NEWLINE);
		ShowMsg("The Attribute CKA_CLASS of this Obj is: CKO_DATA"NEWLINE);
		ShowMsg("The Attribute CKA_LABEL of this Obj is: ");
		ShowMsg(strvale);
		ShowMsg(NEWLINE"The Attribute CKA_APPLICATION of this Obj is:");
		ShowMsg(strApp);		
		ShowMsg(NEWLINE"The Content of this Obj(CKA_VALUE) is:"NEWLINE);
		ShowMsg(nByteToStr(pAttrTemp[3].ulValueLen, pAttrTemp[3].pValue, 1, 16));
		ShowMsg(NEWLINE"Finish Output Obj"NEWLINE);
		
		
		
		delete[] pAttrTemp[0].pValue;
		delete[] pAttrTemp[1].pValue;
		delete[] pAttrTemp[2].pValue;
		delete[] pAttrTemp[3].pValue;		
	}while(true);

	if(numObj==0)
	{
		StartOP();
		ShowMsg(NEWLINE"Can't find Data Obj"NEWLINE);
	}
	else
	{
		StartOP();
		CHAR strNumObj[4];
		wsprintf(strNumObj,"%d",numObj);
		ShowMsg(NEWLINE"Find ");
		ShowMsg(strNumObj);
		ShowMsg(" Data Obj"NEWLINE);
	}


}

void CEnumObjDlg::OnBtnPublic() 
{
	CK_OBJECT_CLASS dataClass = CKO_PUBLIC_KEY;
	BOOL IsToken=true;
	CK_ATTRIBUTE pTempl[] = 
	{
		{CKA_CLASS, &dataClass, sizeof(CKO_PUBLIC_KEY)},
		{CKA_TOKEN, &IsToken, sizeof(true)}
	};

	
	C_FindObjectsInit(m_hSession, pTempl, 2);
	
	CK_OBJECT_HANDLE hCKObj;
	CK_ULONG ulRetCount = 0;
	CK_RV ckrv = 0;
	int numObj=0;
	do
	{
		ckrv = C_FindObjects(m_hSession, &hCKObj, 1, &ulRetCount);
		if(CKR_OK != ckrv)
		{
			break;	
		}
		if(1 != ulRetCount)
			break;
		
		CK_ATTRIBUTE pAttrTemp[] = 
		{
			{CKA_CLASS, NULL, 0},
			{CKA_KEY_TYPE,NULL,0},
			{CKA_LABEL, NULL, 0},
			{CKA_WRAP,NULL,0},
			{CKA_ENCRYPT,NULL,0},
			{CKA_MODULUS,NULL,0},
			{CKA_PUBLIC_EXPONENT,NULL,0},
		};
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 7);
		if(ckrv != CKR_OK)
		{
			break;
		}
		
		pAttrTemp[0].pValue = new char[pAttrTemp[0].ulValueLen];
		pAttrTemp[1].pValue = new char[pAttrTemp[1].ulValueLen];
		pAttrTemp[2].pValue = new char[pAttrTemp[2].ulValueLen+1];
		pAttrTemp[3].pValue = new char[pAttrTemp[3].ulValueLen];
		pAttrTemp[4].pValue = new char[pAttrTemp[4].ulValueLen];
		pAttrTemp[5].pValue = new char[pAttrTemp[5].ulValueLen];
		pAttrTemp[6].pValue = new char[pAttrTemp[6].ulValueLen];
		
		ZeroMemory(pAttrTemp[0].pValue, pAttrTemp[0].ulValueLen);
		ZeroMemory(pAttrTemp[1].pValue, pAttrTemp[1].ulValueLen);
		ZeroMemory(pAttrTemp[2].pValue, pAttrTemp[2].ulValueLen+1);	
		ZeroMemory(pAttrTemp[3].pValue, pAttrTemp[3].ulValueLen);
		ZeroMemory(pAttrTemp[4].pValue, pAttrTemp[4].ulValueLen);
		ZeroMemory(pAttrTemp[5].pValue, pAttrTemp[5].ulValueLen);
		ZeroMemory(pAttrTemp[6].pValue, pAttrTemp[6].ulValueLen);
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 7);
		if(ckrv != CKR_OK)
		{
			delete[] pAttrTemp[0].pValue;
			delete[] pAttrTemp[1].pValue;
			delete[] pAttrTemp[2].pValue;
			delete[] pAttrTemp[3].pValue;
			delete[] pAttrTemp[4].pValue;
			delete[] pAttrTemp[5].pValue;
			delete[] pAttrTemp[6].pValue;
			break;
		}

		numObj++;
		CString strvale = (char*)pAttrTemp[2].pValue;

		
		ShowMsg(NEWLINE);
		StartOP();
		ShowMsg(NEWLINE"Begin this Object's Output:"NEWLINE);
		ShowMsg("The Attribute CKA_CLASS of this Obj is:: CKO_PUBLIC_KEY"NEWLINE);
		
		if(*(int*)pAttrTemp[1].pValue==CKK_RSA)
		{
		ShowMsg("The Attribute CKA_KEY_TYPE is: CKK_RSA"NEWLINE);
		}
		else 
			if(*(int*)pAttrTemp[1].pValue==CKK_DSA)
			{
				ShowMsg("The Attribute CKA_KEY_TYPE is CKK_DSA"NEWLINE);
			}
			else
				if(*(int*)pAttrTemp[1].pValue==CKK_DH)
				{
					ShowMsg("The Attribute CKA_KEY_TYPE is CKK_DH"NEWLINE);					
				}

		ShowMsg("The Attribute CKA_LABEL of this Obj is: ");
		ShowMsg(strvale);
		
		if((int)*(char*)pAttrTemp[3].pValue!=0)
		{
			ShowMsg(NEWLINE"The Attribute CKA_WRAP is: true");
		}
		else
		{
			ShowMsg(NEWLINE"The Attribute CKA_WRAP is: false");
		}

		
		if((int)*(char*)pAttrTemp[4].pValue!=0)
		{
			ShowMsg(NEWLINE"The Attribute CKA_ENCRYPT is: true");
		}
		else
		{
			ShowMsg(NEWLINE"The Attribute CKA_ENCRYPT is: false");
		}
		

		ShowMsg(NEWLINE"The Attribute CKA_MODULUS(public key) is:"NEWLINE);
		ShowMsg(nByteToStr(pAttrTemp[5].ulValueLen, pAttrTemp[5].pValue, 1, 16));
		ShowMsg(NEWLINE"The Attribute CKA_PUBLIC_EXPONENT is:"NEWLINE);
		ShowMsg(nByteToStr(pAttrTemp[6].ulValueLen, pAttrTemp[6].pValue, 1, 16));
		ShowMsg(NEWLINE"Finish Output Obj"NEWLINE);
		
		
		delete[] pAttrTemp[0].pValue;
		delete[] pAttrTemp[1].pValue;
		delete[] pAttrTemp[2].pValue;
		delete[] pAttrTemp[3].pValue;
		delete[] pAttrTemp[4].pValue;
		delete[] pAttrTemp[5].pValue;
		delete[] pAttrTemp[6].pValue;
		
		
	}while(true);
	if(numObj==0)
	{
		StartOP();
		ShowMsg(NEWLINE"Can't find public key Obj"NEWLINE);
	}
	else
	{
		StartOP();
		CHAR strNumObj[4];
		wsprintf(strNumObj,"%d",numObj);
		ShowMsg(NEWLINE"Find ");
		ShowMsg(strNumObj);
		ShowMsg(" public key"NEWLINE);
	}

}

void CEnumObjDlg::OnBtnPrivate() 
{
	// TODO: Add your control notification handler code here
	CK_OBJECT_CLASS dataClass = CKO_PRIVATE_KEY;
	BOOL IsToken=true;
	CK_ATTRIBUTE pTempl[] = 
	{
		{CKA_CLASS, &dataClass, sizeof(CKO_PRIVATE_KEY)},
		{CKA_TOKEN, &IsToken, sizeof(true)}
	};
	
	
	C_FindObjectsInit(m_hSession, pTempl, 2);
	
	CK_OBJECT_HANDLE hCKObj;
	CK_ULONG ulRetCount = 0;
	CK_RV ckrv = 0;
	int numObj=0;
	do
	{
		ckrv = C_FindObjects(m_hSession, &hCKObj, 1, &ulRetCount);
		if(CKR_OK != ckrv)
		{
			break;	
		}
		if(1 != ulRetCount)
			break;
		
		CK_ATTRIBUTE pAttrTemp[] = 
		{
			{CKA_CLASS, NULL, 0},
			{CKA_KEY_TYPE,NULL,0},
			{CKA_LABEL, NULL, 0},
			{CKA_SUBJECT,NULL,0},
			{CKA_ID,NULL,0},
			{CKA_SENSITIVE,NULL,0},
			{CKA_DECRYPT,NULL,0},
			{CKA_SIGN,NULL,0},
			{CKA_MODULUS,NULL,0},
			{CKA_PUBLIC_EXPONENT,NULL,0},
		};
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 10);
		if(ckrv != CKR_OK)
		{
			break;
		}
		
		pAttrTemp[0].pValue = new char[pAttrTemp[0].ulValueLen];
		pAttrTemp[1].pValue = new char[pAttrTemp[1].ulValueLen];
		pAttrTemp[2].pValue = new char[pAttrTemp[2].ulValueLen+1];
		pAttrTemp[3].pValue = new char[pAttrTemp[3].ulValueLen+1];
		pAttrTemp[4].pValue = new char[pAttrTemp[4].ulValueLen+1];
		pAttrTemp[5].pValue = new char[pAttrTemp[5].ulValueLen];
		pAttrTemp[6].pValue = new char[pAttrTemp[6].ulValueLen];
		pAttrTemp[7].pValue = new char[pAttrTemp[7].ulValueLen];
		pAttrTemp[8].pValue = new char[pAttrTemp[8].ulValueLen];
		pAttrTemp[9].pValue = new char[pAttrTemp[9].ulValueLen];
		
		ZeroMemory(pAttrTemp[0].pValue, pAttrTemp[0].ulValueLen);
		ZeroMemory(pAttrTemp[1].pValue, pAttrTemp[1].ulValueLen);
		ZeroMemory(pAttrTemp[2].pValue, pAttrTemp[2].ulValueLen+1);	
		ZeroMemory(pAttrTemp[3].pValue, pAttrTemp[3].ulValueLen+1);
		ZeroMemory(pAttrTemp[4].pValue, pAttrTemp[4].ulValueLen+1);
		ZeroMemory(pAttrTemp[5].pValue, pAttrTemp[5].ulValueLen);
		ZeroMemory(pAttrTemp[6].pValue, pAttrTemp[6].ulValueLen);
		ZeroMemory(pAttrTemp[7].pValue, pAttrTemp[7].ulValueLen);
		ZeroMemory(pAttrTemp[8].pValue, pAttrTemp[8].ulValueLen);
		ZeroMemory(pAttrTemp[9].pValue, pAttrTemp[9].ulValueLen);
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 10);
		if(ckrv != CKR_OK)
		{
			delete[] pAttrTemp[0].pValue;
			delete[] pAttrTemp[1].pValue;
			delete[] pAttrTemp[2].pValue;
			delete[] pAttrTemp[3].pValue;
			delete[] pAttrTemp[4].pValue;
			delete[] pAttrTemp[5].pValue;
			delete[] pAttrTemp[6].pValue;
			delete[] pAttrTemp[7].pValue;
			delete[] pAttrTemp[8].pValue;
			delete[] pAttrTemp[9].pValue;
			//			bRet = false;
			break;
		}
		numObj++;
		
		CString strvale = (char*)pAttrTemp[2].pValue;
		CString strsubject=(char*)pAttrTemp[3].pValue;
		//CString strckaid=(char*)pAttrTemp[4].pValue;
		
		ShowMsg(NEWLINE);
		StartOP();
		ShowMsg(NEWLINE"Begin this Object's Output:"NEWLINE);
		ShowMsg("The Attribute CKA_CLASS of this Obj is:: CKO_PRIVATE_KEY"NEWLINE);
		
		if(*(int*)pAttrTemp[1].pValue==CKK_RSA)
		{
			ShowMsg("The Attribute CKA_KEY_TYPE is : CKK_RSA"NEWLINE);
		}
		else 
			if(*(int*)pAttrTemp[1].pValue==CKK_DSA)
			{
				ShowMsg("The Attribute CKA_KEY_TYPE is CKK_DSA"NEWLINE);
			}
			else
				if(*(int*)pAttrTemp[1].pValue==CKK_DH)
				{
					ShowMsg("The Attribute CKA_KEY_TYPE is CKK_DH"NEWLINE);					
				}
				
		ShowMsg("The Attribute CKA_LABEL of this Obj is: ");
		ShowMsg(strvale);
		ShowMsg(NEWLINE"The Attribute CKA_ID of this Obj is: "NEWLINE);
		//ShowMsg(strckaid);
		ShowMsg(nByteToStr(pAttrTemp[4].ulValueLen, pAttrTemp[4].pValue, 1, 16));
			
		if((int)*(char*)pAttrTemp[5].pValue!=0)
		{
			ShowMsg(NEWLINE"The Attribute CKA_SENSITIVE is: true");
		}
		else
		{
			ShowMsg(NEWLINE"The Attribute CKA_SENSITIVE is: false");
		}
			
			
		if((int)*(char*)pAttrTemp[6].pValue!=0)
		{
			ShowMsg(NEWLINE"The Attribute CKA_DECRYPT is: true");
		}
		else
		{
			ShowMsg(NEWLINE"The Attribute CKA_DECRYPT is: false");
		}

		if((int)*(char*)pAttrTemp[7].pValue!=0)
		{
			ShowMsg(NEWLINE"The Attribute CKA_SIGN is: true");
		}
		else
		{
			ShowMsg(NEWLINE"The Attribute CKA_SIGN is: false");
		}
			
			
		ShowMsg(NEWLINE"Private Key can't output because of the limit of hardware:"NEWLINE);

		
		ShowMsg(NEWLINE"Finish Output Obj"NEWLINE);
		
		
		delete[] pAttrTemp[0].pValue;
		delete[] pAttrTemp[1].pValue;
		delete[] pAttrTemp[2].pValue;
		delete[] pAttrTemp[3].pValue;
		delete[] pAttrTemp[4].pValue;
		delete[] pAttrTemp[5].pValue;
		delete[] pAttrTemp[6].pValue;
		delete[] pAttrTemp[7].pValue;
		delete[] pAttrTemp[8].pValue;
		delete[] pAttrTemp[9].pValue;

	}while(true);
	
	if(numObj==0)
	{
		StartOP();
		ShowMsg(NEWLINE"Can's find private key Obj"NEWLINE);
	}
	else
	{
		StartOP();
		CHAR strNumObj[4];
		wsprintf(strNumObj,"%d",numObj);
		ShowMsg(NEWLINE"Find ");
		ShowMsg(strNumObj);
		ShowMsg(" private key"NEWLINE);
	}
	
}

void CEnumObjDlg::OnBtnSecret() 
{
	// TODO: Add your control notification handler code here
	CK_OBJECT_CLASS dataClass = CKO_SECRET_KEY;
	BOOL IsToken=true;
	CK_ATTRIBUTE pTempl[] = 
	{
		{CKA_CLASS, &dataClass, sizeof(CKO_PUBLIC_KEY)},
		{CKA_TOKEN, &IsToken, sizeof(true)}
	};

	
	C_FindObjectsInit(m_hSession, pTempl, 2);
	
	CK_OBJECT_HANDLE hCKObj;
	CK_ULONG ulRetCount = 0;
	CK_RV ckrv = 0;

	int numObj=0;

	do
	{
		ckrv = C_FindObjects(m_hSession, &hCKObj, 1, &ulRetCount);
		if(CKR_OK != ckrv)
		{
			break;
		}
		if(1 != ulRetCount)
			break;
		
		CK_ATTRIBUTE pAttrTemp[] = 
		{
			{CKA_CLASS, NULL, 0},
			{CKA_KEY_TYPE,NULL,0},
			{CKA_LABEL, NULL, 0},
			{CKA_DERIVE,NULL,0},
			{CKA_VALUE,NULL,0},
		};
		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 5);
		if(ckrv != CKR_OK)
		{
			break;
		}
		
		pAttrTemp[0].pValue = new char[pAttrTemp[0].ulValueLen];
		pAttrTemp[1].pValue = new char[pAttrTemp[1].ulValueLen];
		pAttrTemp[2].pValue = new char[pAttrTemp[2].ulValueLen+1];
		pAttrTemp[3].pValue = new char[pAttrTemp[3].ulValueLen];
		pAttrTemp[4].pValue = new char[pAttrTemp[4].ulValueLen];

		
		ZeroMemory(pAttrTemp[0].pValue, pAttrTemp[0].ulValueLen);
		ZeroMemory(pAttrTemp[1].pValue, pAttrTemp[1].ulValueLen);
		ZeroMemory(pAttrTemp[2].pValue, pAttrTemp[2].ulValueLen+1);	
		ZeroMemory(pAttrTemp[3].pValue, pAttrTemp[3].ulValueLen);
		ZeroMemory(pAttrTemp[4].pValue, pAttrTemp[4].ulValueLen);

		
		ckrv = C_GetAttributeValue(m_hSession, hCKObj, pAttrTemp, 5);
		if(ckrv != CKR_OK)
		{
			delete[] pAttrTemp[0].pValue;
			delete[] pAttrTemp[1].pValue;
			delete[] pAttrTemp[2].pValue;
			delete[] pAttrTemp[3].pValue;
			delete[] pAttrTemp[4].pValue;
			break;
		}

		numObj++;

		CString strvale = (char*)pAttrTemp[2].pValue;

		
		ShowMsg(NEWLINE);
		StartOP();
		ShowMsg(NEWLINE"Begin this Object's Output:"NEWLINE);
		ShowMsg("The Attribute CKA_CLASS of this Obj is:: CKO_SECRET_KEY"NEWLINE);
		
		if(*(int*)pAttrTemp[1].pValue==CKK_GENERIC_SECRET)
		{
		ShowMsg("The Attribute CKA_KEY_TYPE is: CKK_GENERIC_SECRET"NEWLINE);
		}
		else 
			if(*(int*)pAttrTemp[1].pValue==CKK_RC2)
			{
				ShowMsg("The Attribute CKA_KEY_TYPE is CKK_RC2"NEWLINE);
			}
			else
				if(*(int*)pAttrTemp[1].pValue==CKK_RC4)
				{
					ShowMsg("The Attribute CKA_KEY_TYPE is CKK_RC4"NEWLINE);					
				}
				else
					if(*(int*)pAttrTemp[1].pValue==CKK_DES)
					{
						ShowMsg("The Attribute CKA_KEY_TYPE is CKK_DES"NEWLINE);					
					}
					else
						if(*(int*)pAttrTemp[1].pValue==CKK_DES2)
						{
							ShowMsg("The Attribute CKA_KEY_TYPE is CKK_DES2"NEWLINE);					
						}
						else
							if(*(int*)pAttrTemp[1].pValue==CKK_DES3)
							{
								ShowMsg("The Attribute CKA_KEY_TYPE is CKK_DES3"NEWLINE);					
							}
					
		ShowMsg("The Attribute CKA_LABEL of this Obj is: ");
		ShowMsg(strvale);
		
		if((int)*(char*)pAttrTemp[3].pValue!=0)
		{
			ShowMsg(NEWLINE"The Attribute CKA_DERIVE is: true");
		}
		else
		{
			ShowMsg(NEWLINE"The Attribute CKA_DERIVE is : false");
		}

		ShowMsg(NEWLINE"CKA_VALUE(Content of key) is:"NEWLINE);
		ShowMsg(nByteToStr(pAttrTemp[4].ulValueLen, pAttrTemp[5].pValue, 1, 16));
		
		ShowMsg(NEWLINE"Finish Output Obj"NEWLINE);
		
		delete[] pAttrTemp[0].pValue;
		delete[] pAttrTemp[1].pValue;
		delete[] pAttrTemp[2].pValue;
		delete[] pAttrTemp[3].pValue;
		delete[] pAttrTemp[4].pValue;
		
	}while(true);
	

	if(numObj==0)
	{
		StartOP();
		ShowMsg(NEWLINE"Can't find secret key"NEWLINE);
	}
	else
	{
		StartOP();
		CHAR strNumObj[4];
		wsprintf(strNumObj,"%d",numObj);
		ShowMsg(NEWLINE"Find ");
		ShowMsg(strNumObj);
		ShowMsg(" secret key"NEWLINE);
	}
}

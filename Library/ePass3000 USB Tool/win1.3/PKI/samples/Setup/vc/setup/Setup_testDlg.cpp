// Setup_testDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Setup_test.h"
#include "Setup_testDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

typedef unsigned long (__stdcall* esa_DoInstall)(char* szParam);
typedef unsigned long (__stdcall* esa_IsHaveInstalled)(char* szParam);
typedef unsigned long (__stdcall* esa_IsNeedReboot)(void);
typedef unsigned long (__stdcall* esa_DoUnInstall)(char* szParam);
typedef unsigned long  (WINAPI *WirteSetReg)(char*);

esa_DoInstall InstallMW = NULL;
esa_IsHaveInstalled IsHaveInstalled = NULL;
esa_IsNeedReboot IsNeedReboot = NULL;
esa_DoUnInstall UnInstallMW = NULL;
WirteSetReg pWirteSetReg = NULL;


/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

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
// CSetup_testDlg dialog

CSetup_testDlg::CSetup_testDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSetup_testDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CSetup_testDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSetup_testDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSetup_testDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CSetup_testDlg, CDialog)
	//{{AFX_MSG_MAP(CSetup_testDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_UNINSTALL, OnUninstall)
	ON_BN_CLICKED(IDC_ISNEEDREBOOT, OnIsneedreboot)
	ON_BN_CLICKED(IDC_ISHAVEINST, OnIshaveinst)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSetup_testDlg message handlers

BOOL CSetup_testDlg::OnInitDialog()
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
	
	m_hinstLib = LoadLibrary( "NGSetup.dll" );
	if (m_hinstLib == NULL)
	{
		AfxMessageBox("Load Library NGSetup.dll Error!");
		exit(1);
	}
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CSetup_testDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CSetup_testDlg::OnPaint() 
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
HCURSOR CSetup_testDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CSetup_testDlg::OnOK() 
{
	DWORD dwRet;
	InstallMW =  (esa_DoInstall)GetProcAddress(m_hinstLib, "instMW_Install");
	if(NULL != InstallMW)
	{
		dwRet = InstallMW(";regatr=true");
		if(dwRet != ESA_SUCCESS)
		{
			CString strTemp;
			strTemp.Format("InstMW_Install error! return is %d",dwRet);
			AfxMessageBox(strTemp);
			return;
		}
	}
	else
		AfxMessageBox("Can not GetProcAddress.");
	AfxMessageBox("ESA_SUCCESS");
	return;
}

void CSetup_testDlg::OnUninstall() 
{
	DWORD dwRet;
	UnInstallMW =  (esa_DoUnInstall)GetProcAddress(m_hinstLib, "instMW_Uninstall");
	if(NULL != UnInstallMW)
	{
		dwRet = UnInstallMW("");
		if(dwRet != ESA_SUCCESS)
		{
			CString strTemp;
			strTemp.Format("InstMW_Install error! return is %d",dwRet);
			AfxMessageBox(strTemp);
			return;
		}
	}
	else
		AfxMessageBox("Can not GetProcAddress.");
	AfxMessageBox("ESA_SUCCESS");
	return;
}

void CSetup_testDlg::OnIsneedreboot() 
{
	DWORD dwRet;
	IsNeedReboot =  (esa_IsNeedReboot)GetProcAddress(m_hinstLib, "instMW_IsNeedReboot");
	if(NULL != IsNeedReboot)
	{
		dwRet = IsNeedReboot();
		if(dwRet != ESA_SUCCESS)
		{
			AfxMessageBox("Need Reboot");
			return;
		}
	}
	else
		AfxMessageBox("Can not GetProcAddress.");
	AfxMessageBox("Needn't reboot");
	return;
}

void CSetup_testDlg::OnIshaveinst() 
{
	DWORD dwRet;
	IsHaveInstalled =  (esa_IsHaveInstalled)GetProcAddress(m_hinstLib, "instMW_IsHaveInstalled");
	if(NULL != IsHaveInstalled)
	{
		dwRet = IsHaveInstalled("");
		if(dwRet == ESA_NEVER_INSTALL)
		{
			AfxMessageBox("ESA_NEVER_INSTALL");
			return;
		}
		if(dwRet == ESA_DEST_DVERSION_OLD)
		{
			AfxMessageBox("ESA_DEST_DVERSION_OLD");
			return;
		}
		if(dwRet == ESA_DEST_DVERSION_EQUAL)
		{
			AfxMessageBox("ESA_DEST_DVERSION_EQUAL");
			return;
		}
		if(dwRet == ESA_DEST_DVERSION_NEW)
		{
			AfxMessageBox("ESA_DEST_DVERSION_NEW");
			return;
		}
	}
	else
		AfxMessageBox("Can not GetProcAddress.");
	AfxMessageBox("ESA_SUCCESS");
	return;
}

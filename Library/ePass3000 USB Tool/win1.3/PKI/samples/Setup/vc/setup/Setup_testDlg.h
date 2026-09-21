// Setup_testDlg.h : header file
//

#if !defined(AFX_SETUP_TESTDLG_H__65F4E66A_CE5F_499C_986A_3E64BD08529D__INCLUDED_)
#define AFX_SETUP_TESTDLG_H__65F4E66A_CE5F_499C_986A_3E64BD08529D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CSetup_testDlg dialog
#define ESA_NEVER_INSTALL					0
#define ESA_DEST_DVERSION_OLD				1
#define ESA_DEST_DVERSION_EQUAL				2
#define ESA_DEST_DVERSION_NEW				3

#define ESA_SUCCESS								0x0000
#define ESA_ERR_FILE_NOT_FOUND					0x0001
#define ESA_ERR_COPY_FILES						0x0002
#define ESA_ERR_REG								0x0003
#define ESA_ERR_REG_CSP							0x0004
#define ESA_ERR_UNREG							0x0005
#define ESA_ERR_DEL_FILES						0x0006
#define ESA_ERR_DEL_DIR							0x0007
#define ESA_ERR_EXCTOR_FILES					0x0008
#define ESA_ERR_HOST_MEMORY						0x0009
#define ESA_ERR_REG_CARD_REG					0x000A

class CSetup_testDlg : public CDialog
{
// Construction
public:
	CSetup_testDlg(CWnd* pParent = NULL);	// standard constructor
	bool IsWin98();

// Dialog Data
	//{{AFX_DATA(CSetup_testDlg)
	enum { IDD = IDD_SETUP_TEST_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSetup_testDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

	HMODULE m_hinstLib;

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CSetup_testDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	virtual void OnOK();
	afx_msg void OnButton1();
	afx_msg void OnButton2();
	afx_msg void OnButton3();
	afx_msg void OnUninstall();
	afx_msg void OnIsneedreboot();
	afx_msg void OnIshaveinst();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SETUP_TESTDLG_H__65F4E66A_CE5F_499C_986A_3E64BD08529D__INCLUDED_)

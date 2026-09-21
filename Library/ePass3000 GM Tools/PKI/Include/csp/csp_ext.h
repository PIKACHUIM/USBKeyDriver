/*
[]=========================================================================[]

	Copyright(C) 2000-2004, Feitian Technologies Co., Ltd.
	ePass Team
	All rights reserved.

FILE:
	csp_ext.h

DESC:
	

REVISION:
	2004-01-14 [Apex Liu]
		Created.
	2004-07-13 [Skybird Le]
		Add SSF33 support.
[]=========================================================================[]
*/

#ifndef __EPSNG_CSP_CONST_FEITIAN_H__
#define __EPSNG_CSP_CONST_FEITIAN_H__

#define CSP_NAME "EnterSafe ePass3000GM CSP v1.0"

// algorithm extended by Ftsafe
#define ALG_SID_SSF33			0xFF
#define CALG_SSF33			(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SSF33)
#define CALG_IDEA           (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_IDEA)
#define CALG_AES            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES)

#define ALG_SID_SM1			102
#define CALG_SM1			(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SM1)

#define ALG_SID_SMS4		40
#define CALG_SMS4			(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SMS4)

#define ALG_SID_SM3			30
#define CALG_SM3			(ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SM3)


#define ALG_SID_SM2			20
#define CALG_SM2_SIGN           (ALG_CLASS_SIGNATURE | ALG_SID_SM2 | ALG_SID_RSA_ANY)
#define CALG_SM2_KEYX           (ALG_CLASS_KEY_EXCHANGE|ALG_SID_SM2|ALG_SID_RSA_ANY)


#define HP_USERID				0x81
#define HP_SM2_PUBLICKEY		0x82
		

#endif // __EPS2K_CSP_CONST_FEITIAN_H__

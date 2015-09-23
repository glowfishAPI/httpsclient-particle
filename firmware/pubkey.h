/**
 *	@file    pubkey.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Public and Private key header.
 */
/*
 *	Copyright (c) 2013-2015 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software
 *	into proprietary programs.  If you are unable to comply with the GPL, a
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/eng/Company/Locations
 *
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *	See the GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#ifndef _h_PS_PUBKEY
#define _h_PS_PUBKEY

#define PUBKEY_TYPE		0x01
#define PRIVKEY_TYPE	0x02

/* Public Key types for psPubKey_t */
#define PS_RSA	1
#define	PS_ECC	2
#define PS_DH	3

/* Sig types */
#define	RSA_TYPE_SIG			5
#define	DSA_TYPE_SIG			6
#define RSAPSS_TYPE_SIG			7

/*
	Pub key speed or size optimization handling
*/
#if defined(PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED) &&	defined(PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM)
#error "May only enable either PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED or PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM"
#endif

#if !defined(PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED) && !defined(PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM)
#define PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#endif

#ifdef PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#define PS_EXPTMOD_WINSIZE		3
#endif

#ifdef PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED
#define PS_EXPTMOD_WINSIZE		5
#endif

/******************************************************************************/
#ifdef USE_RSA
/******************************************************************************/
/*
	Primary RSA Key struct.  Define here for crypto
*/
typedef struct {
	pstm_int    e, d, N, qP, dP, dQ, p, q;
	uint32      size;   /* Size of the key in bytes */
	int32       optimized; /* 1 for optimized */
	psPool_t *pool;
} psRsaKey_t;


#endif /* USE_RSA */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_ECC
/******************************************************************************/
#define ECC_MAXSIZE	132 /* max private key size */


#define IS_SECP192R1	0x00000001
#define IS_SECP224R1	0x00000002
#define IS_SECP256R1	0x00000004
#define IS_SECP384R1	0x00000008
#define IS_SECP521R1	0x00000010
/* WARNING: Public points on Brainpool curves are not validated */
#define IS_BRAIN224R1	0x00100000
#define IS_BRAIN256R1	0x00200000
#define IS_BRAIN384R1	0x00400000
#define IS_BRAIN512R1	0x00800000


typedef struct {
	int32 size; /* The size of the curve in octets */
	int32 curveId; /* IANA named curve id for TLS use */
	int32 OIDsum; /* Matrix OID */
#ifdef USE_PKCS11_ECC
	CK_BYTE oid[10]; /* OID bytes */
	int		oidLen; /* OID bytes */
#else
	int32 isOptimized; /* 1 if this is an optimized curve with field parameter
							A=-3, zero otherwise. */
#endif
	char *name;  /* name of curve */
	char *prime; /* prime defining the field the curve is in (encoded in hex) */
	char *A; /* The fields A param (hex) */
	char *B; /* The fields B param (hex) */
	char *order; /* The order of the curve (hex) */
	char *Gx; /* The x co-ordinate of the base point on the curve (hex) */
	char *Gy; /* The y co-ordinate of the base point on the curve (hex) */
} psEccSet_t;

/*	A point on a ECC curve, stored in Jacbobian format such that
	 (x,y,z) => (x/z^2, y/z^3, 1) when interpretted as affine
 */
typedef struct {
	psPool_t *pool;
	pstm_int x; /* The x co-ordinate */
	pstm_int y; /* The y co-ordinate */
	pstm_int z;  /* The z co-ordinate */
} psEccPoint_t;

#ifdef USE_NATIVE_ECC
typedef struct {
	psPool_t			*pool;
	int32				type;	/* Type of key, PK_PRIVATE or PK_PUBLIC */
	psEccSet_t			*dp;	/* pointer to domain parameters; */
	psEccPoint_t		pubkey;	/* The public key */
	pstm_int			k;		/* The private key */
} psEccKey_t;

#endif
#ifdef USE_PKCS11_ECC
typedef struct {
	unsigned char		*value;
	int32				valueLen;
} pkcs11EcKey_t;

typedef struct {
	psPool_t			*pool;
	int32				type;	/* Type of key, PK_PRIVATE or PK_PUBLIC */
	psEccSet_t			*dp;	/* pointer to domain parameters; */
	pkcs11EcKey_t		pubkey;
	pkcs11EcKey_t		k;  /* private key */
#ifdef USE_UNIFIED_PKCS11
	CK_SESSION_HANDLE	sess; /* keys stay internal to module */
	CK_OBJECT_HANDLE	obj;
	int32				external; /* Did we create the object? */
#endif
} psEccKey_t;
#endif

extern void	psGetEccCurveIdList(char *curveList, uint32 *len);
extern void userSuppliedEccList(char *curveList, uint32 *len, int32 curves);
extern int32 compiledInEcFlags(void);
extern int32 getEcPubKey(psPool_t *pool, unsigned char **pp, int32 len,
				psEccKey_t *pubKey);

extern int32 getEccParamById(int32 curveId, psEccSet_t **set);
extern int32 getEccParamByName(char *curveName, psEccSet_t **set);
extern int32 getEccParamByOid(int32 oid, psEccSet_t **set);

#endif /* USE_ECC */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DH
/******************************************************************************/
typedef struct {
	int32	type;
	uint32	size;
	pstm_int	priv, pub;
} psDhKey_t;

typedef struct {
	psPool_t	*pool;
	uint32		size;
	pstm_int	p, g;
} psDhParams_t;

#endif /* USE_DH */
/******************************************************************************/

/******************************************************************************/
/*
	Univeral public key type

	The pubKey name comes from the generic public-key crypto terminology and
	does not mean these key are restricted to the public side only. These
	may be private keys.
*/
/******************************************************************************/

typedef union {
#ifdef USE_RSA
	psRsaKey_t	rsa;
#else
	short		notEmpty; /* Prevents from being empty */
#endif /* USE_RSA */
#ifdef USE_ECC
	psEccKey_t	ecc;
#endif /* USE_ECC */
} pubKeyUnion_t;

typedef struct {
	pubKeyUnion_t	*key;
	uint32			keysize; /* in bytes */
	int32			type; /* PS_RSA, PS_ECC, PS_DH */
	psPool_t		*pool;
} psPubKey_t;


/******************************************************************************/
/*
	Internal helpers
*/
extern int32 pkcs1Pad(unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, int32 cryptType, void *userPtr);
extern int32 pkcs1Unpad(unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, int32 decryptType);

#ifdef USE_RSA
extern void psRsaFreeKey(psRsaKey_t *key);
#endif /* USE_RSA */
/******************************************************************************/
#endif /* _h_PS_PUBKEY */


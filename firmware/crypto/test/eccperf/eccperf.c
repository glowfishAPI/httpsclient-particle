/**
 *	@file    eccperf.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	ECC performance testing	.
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

#include "crypto/cryptoApi.h"

#ifdef USE_ECC

/* OPERATIONS TO TEST */
#define SIGN_OP		/* Private encrypt operations */
#define VERIFY_OP	/* Public decrypt operations */
#define MAKE_KEY_OP	/* DH key gen operations */

/* CURVES TO TEST */
#define DO_SECP192R1
#define DO_SECP224R1
#define DO_SECP256R1
#define DO_SECP384R1
//#define DO_SECP521R1
//#define DO_BRAIN256R1
//#define DO_BRAIN384R1
//#define DO_BRAIN512R1

/* NUMBER OF OPERATIONS */
#define ITER 20


#define PS_OH sizeof(psPool_t)

/*
	TODO: Not tuned to smallest K for EACH key size.
*/
#define POOL_SIGN_192		(8 * 1024) + PS_OH
#define POOL_VERIFY_192		(8 * 1024) + PS_OH
#define POOL_MAKE_KEY_192	(8 * 1024) + PS_OH
#define POOL_MISC_192		(8 * 1024) + PS_OH

#define POOL_SIGN_224		(8 * 1024) + PS_OH
#define POOL_VERIFY_224		(8 * 1024) + PS_OH
#define POOL_MAKE_KEY_224	(8 * 1024) + PS_OH
#define POOL_MISC_224		(8 * 1024) + PS_OH

#define POOL_SIGN_256		(8 * 1024) + PS_OH
#define POOL_VERIFY_256		(8 * 1024) + PS_OH
#define POOL_MAKE_KEY_256	(8 * 1024) + PS_OH
#define POOL_MISC_256		(8 * 1024) + PS_OH

#define POOL_SIGN_384		(12 * 1024) + PS_OH
#define POOL_VERIFY_384		(12 * 1024) + PS_OH
#define POOL_MAKE_KEY_384	(12 * 1024) + PS_OH
#define POOL_MISC_384		(12 * 1024) + PS_OH

#define POOL_SIGN_521		(12 * 1024) + PS_OH
#define POOL_VERIFY_521		(12 * 1024) + PS_OH
#define POOL_MAKE_KEY_521	(12 * 1024) + PS_OH
#define POOL_MISC_521		(12 * 1024) + PS_OH

#ifdef DO_SECP192R1
#include "test/eccperf/secp192r1-key.h"
#endif
#ifdef DO_SECP224R1
#include "test/eccperf/secp224r1-key.h"
#endif
#ifdef DO_SECP256R1
#include "test/eccperf/secp256r1-key.h"
#endif
#ifdef DO_SECP384R1
#include "test/eccperf/secp384r1-key.h"
#endif
#ifdef DO_SECP521R1
#include "test/eccperf/secp521r1-key.h"
#endif
#ifdef DO_BRAIN256R1
#include "test/eccperf/brainpoolp256r1.h"
#endif
#ifdef DO_BRAIN384R1
#include "test/eccperf/brainpoolp384r1.h"
#endif
#ifdef DO_BRAIN512R1
#include "test/eccperf/brainpoolp512r1.h"
#endif

typedef struct {
	char				*name;
	const unsigned char	*key;
	uint32				len;
	int32				iter;
	int32				poolSign;
	int32				poolVerify;
	int32				poolMakeKey;
	int32				poolMisc;
} keyList_t;

#ifdef USE_HIGHRES_TIME
  #define psDiffMsecs(A, B, C) psDiffUsecs(A, B)
  #define TIME_UNITS "    %lld usecs"
#else
  #define TIME_UNITS "    %d msecs"
#endif

/*
	Add an iteration count so we don't have to run the large keys so many times
*/
static keyList_t keys[] = {
#ifdef DO_SECP192R1
	{"secp192r1", secp192r1key, sizeof(secp192r1key), ITER, POOL_SIGN_192,
		POOL_VERIFY_192, POOL_MAKE_KEY_192, POOL_MISC_192},
#endif
#ifdef DO_SECP224R1
	{"secp224r1", secp224r1key, sizeof(secp224r1key), ITER, POOL_SIGN_224,
		POOL_VERIFY_224, POOL_MAKE_KEY_224, POOL_MISC_224},
#endif
#ifdef DO_SECP256R1
	{"secp256r1", secp256r1key, sizeof(secp256r1key), ITER, POOL_SIGN_256,
		POOL_VERIFY_256, POOL_MAKE_KEY_256, POOL_MISC_256},
#endif
#ifdef DO_SECP384R1
	{"secp384r1", secp384r1key, sizeof(secp384r1key), ITER, POOL_SIGN_384,
		POOL_VERIFY_384, POOL_MAKE_KEY_384, POOL_MISC_384},
#endif
#ifdef DO_SECP521R1
	{"secp521r1", secp521r1key, sizeof(secp521r1key), ITER, POOL_SIGN_521,
		POOL_VERIFY_521, POOL_MAKE_KEY_521, POOL_MISC_521},
#endif
#ifdef DO_BRAIN256R1
	{"brainpoolp256r1", brainpoolp256r1, sizeof(brainpoolp256r1),
		ITER, POOL_SIGN_256, POOL_VERIFY_256, POOL_MAKE_KEY_256, POOL_MISC_256},
#endif
#ifdef DO_BRAIN384R1
	{"brainpoolp384r1", brainpoolp384r1, sizeof(brainpoolp384r1),
		ITER, POOL_SIGN_384, POOL_VERIFY_384, POOL_MAKE_KEY_384, POOL_MISC_384},
#endif
#ifdef DO_BRAIN512R1
	{"brainpoolp512r1", brainpoolp512r1, sizeof(brainpoolp512r1),
		ITER, POOL_SIGN_521, POOL_VERIFY_521, POOL_MAKE_KEY_521, POOL_MISC_521},
#endif
	{NULL, NULL, 0, 0, 0, 0, 0}
};

/******************************************************************************/
/*
	Main
*/


#ifdef STATS
	#include <unistd.h>
	#include <fcntl.h>
#ifdef USE_HIGHRES_TIME
	#define TIME_STRING "\t%lld"
#else
	#define TIME_STRING "\t%d"
#endif
#endif

int main(int argc, char **argv)
{
	psPool_t		*pool, *misc;
	psPubKey_t		*privkey;
	psEccKey_t		*eccKey;
	unsigned char	*in, *out, *savein, *saveout;
	psTime_t		start, end;
	uint32			iter, i = 0;
	int32			t, validateStatus, signLen;
#ifdef STATS
	FILE			*sfd;
#endif

	pool = misc = NULL;
	if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS) {
		_psTrace("Failed to initialize library:  psCryptoOpen failed\n");
		return -1;
	}
	_psTraceStr("STARTING ECCPERF\n", NULL);
#ifdef STATS
	if ((sfd = fopen("perfstat.txt", "w")) == NULL) {
		return PS_FAILURE;
	}
#ifdef USE_HIGHRES_TIME
	fprintf(sfd, "Key\tSign(usec)\tVerify\tEncrypt\tDecrypt\n");
#else
	fprintf(sfd, "Key\tSign(msec)\tVerify\tEncrypt\tDecrypt\n");
#endif
#endif /* STATS */

	while (keys[i].key != NULL) {
		_psTraceStr("Test %s...\n", keys[i].name);
#ifdef STATS
		fprintf(sfd, "%s", keys[i].name);
#endif
		psEcdsaParsePrivKey(misc, (unsigned char*)keys[i].key, keys[i].len,
			&privkey, NULL);
		savein = in = psMalloc(misc, SHA1_HASH_SIZE);
		psGetEntropy(in, SHA1_HASH_SIZE, NULL);
		signLen = privkey->keysize + 8;
		saveout = out = psMalloc(misc, signLen);

#ifdef MAKE_KEY_OP
		iter = 0;
		psGetTime(&start, NULL);
		while (iter < keys[i].iter) {
			if (psEccMakeKeyEx(pool, &eccKey, privkey->key->ecc.dp, NULL) < 0) {
				_psTrace("	FAILED OPERATION\n");
			}

			psEccFreeKey(&eccKey);
			iter++;
		}
		psGetTime(&end, NULL);
		_psTraceInt(TIME_UNITS "/keyGen\n",
			t = psDiffMsecs(start, end, NULL)/keys[i].iter);
#ifdef STATS
		fprintf(sfd, TIME_STRING, t);
#endif
#endif /* MAKE_KEY_OP */


#ifdef SIGN_OP
		iter = 0;
		psGetTime(&start, NULL);
		while (iter < keys[i].iter) {
			if (psEccSignHash(pool, in, SHA1_HASH_SIZE, out,
					signLen, &privkey->key->ecc, &signLen, 1, NULL) < 0) {
				_psTrace("	FAILED OPERATION\n");
			}
			iter++;
		}
		psGetTime(&end, NULL);
		_psTraceInt(TIME_UNITS "/sig\n",
			t = psDiffMsecs(start, end, NULL)/keys[i].iter);
#ifdef STATS
		fprintf(sfd, TIME_STRING, t);
#endif
#endif /* SIGN_OP */

#ifdef VERIFY_OP
		iter = 0;
		psGetTime(&start, NULL);
		while (iter < keys[i].iter) {
			if (psEcDsaValidateSignature(pool, &privkey->key->ecc, out + 2,
					signLen - 2, in, SHA1_HASH_SIZE, &validateStatus, NULL)
					< 0) {
				_psTrace("	FAILED OPERATION\n");
			}
			iter++;
		}
		psGetTime(&end, NULL);
		_psTraceInt(TIME_UNITS "/verify\n", t = psDiffMsecs(start, end, NULL));
#ifdef STATS
		fprintf(sfd, TIME_STRING, t);
#endif
#endif /* VERIFY_OP */

		psFree(savein, misc);
		psFree(saveout, misc);
		psFreePubKey(privkey);
		i++;
	}

#ifdef STATS
	fclose(sfd);
#endif
#ifdef WIN32
	_psTrace("Press any key to close");
	getchar();
#endif
	_psTraceStr("FINISHED ECCPERF\n", NULL);
	psCryptoClose();
	return 0;
}

#else
int main(int argc, char **argv) {
	printf("USE_ECC not defined.\n");
	return 0;
}
#endif /* USE_ECC */


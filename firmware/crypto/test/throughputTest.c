/**
 *	@file    throughputTest.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
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

#define	DATABYTES_AMOUNT	100 * 1048576	/* # x 1MB (1024-byte variety) */

#define TINY_CHUNKS		16
#define SMALL_CHUNKS	256
#define MEDIUM_CHUNKS	1024
#define LARGE_CHUNKS	4096
#define HUGE_CHUNKS		16 * 1024

static unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static unsigned char key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

#define AES_ALG		1
#define ARC4_ALG	2
#define DES3_ALG	3
#define SEED_ALG	4
#define AES_GCM_ALG	5
#define IDEA_ALG	6


#define SHA1_ALG	1
#define SHA224_ALG	2
#define SHA256_ALG	3
#define SHA384_ALG	4
#define SHA512_ALG	5
#define MD5_ALG		6

static void runTime(psCipherContext_t *ctx, int32 chunk, int32 alg)
{
	psTime_t			start, end;
	unsigned char		*dataChunk;
	int32				bytesSent, bytesToSend, round;
#ifdef USE_HIGHRES_TIME
	int32				mod;
	int64				diffu;
#else
	int32				diffm;
#endif

	dataChunk = psMalloc(NULL, chunk);
	memset(dataChunk, 0x0, chunk);
	bytesToSend = (DATABYTES_AMOUNT / chunk) * chunk;
	bytesSent = 0;

	if (alg == AES_ALG) {
#ifdef USE_AES
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			if (psAesEncrypt(ctx, dataChunk, dataChunk, chunk) < 0)  {
				printf("AES-CBC encrypt error\n");
				return;
			}
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
#endif
#ifdef USE_ARC4
	} else if (alg == ARC4_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			if (psArc4(ctx, dataChunk, dataChunk, chunk) < 0)  {
				printf("ARC4 encrypt error\n");
				return;
			}
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
#endif
#ifdef USE_3DES
	} else if (alg == DES3_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			if (psDes3Encrypt(ctx, dataChunk, dataChunk, chunk) < 0)  {
				printf("3DES encrypt error\n");
				return;
			}
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
#endif
#ifdef USE_AES_GCM
	} else if (alg == AES_GCM_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			if (psAesEncryptGCM(ctx, dataChunk, dataChunk, chunk) < 0)  {
				printf("SEED encrypt error\n");
				return;
			}
			bytesSent += chunk;
		}
		psAesGetGCMTag(ctx, 16, dataChunk);
		psGetTime(&end, NULL);
#endif
#ifdef USE_SEED
	} else if (alg == SEED_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			if (psSeedEncrypt(ctx, dataChunk, dataChunk, chunk) < 0)  {
				printf("SEED encrypt error\n");
				return;
			}
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
#endif
#ifdef USE_IDEA
	} else if (alg == IDEA_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			if (psIdeaEncrypt(ctx, dataChunk, dataChunk, chunk) < 0)  {
				printf("IDEA encrypt error\n");
				return;
			}
			bytesSent += chunk;
		}
		psGetTime(&end, NULL);
#endif
	} else {
		return;
	}

	psFree(dataChunk, NULL);

#ifdef USE_HIGHRES_TIME
	diffu = psDiffUsecs(start, end);
	round = (bytesToSend / diffu);
	mod = (bytesToSend % diffu);
	printf("%d byte chunks in %lld usecs total for rate of %d.%d MB/sec\n",
		chunk, diffu, round, mod);
#else
	diffm = psDiffMsecs(start, end, NULL);
	round = (bytesToSend / diffm) / 1000;
	printf("%d byte chunks in %d msecs total for rate of %d MB/sec\n",
		chunk, diffm, round);
#endif

}

/******************************************************************************/
#ifdef USE_AES
static int32 psAesTestCBC(void)
{
	int32				err;
	psCipherContext_t	eCtx;

#if !defined PS_AES_IMPROVE_PERF_INCREASE_CODESIZE && !defined USE_AESNI_CRYPTO
	_psTrace("##########\n#\n# ");
	_psTrace("AES speeds can be improved by enabling\n# ");
	_psTrace("PS_AES_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
	_psTrace("#\n#\n#########\n");
#endif
	_psTrace("***** AES-128 CBC *****\n");
	if ((err = psAesInit(&eCtx, iv, key, 16)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  psAesInit returned %d\n", err);
 		return err;
	}
	runTime(&eCtx, TINY_CHUNKS, AES_ALG);
	runTime(&eCtx, SMALL_CHUNKS, AES_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, AES_ALG);
	runTime(&eCtx, LARGE_CHUNKS, AES_ALG);
	runTime(&eCtx, HUGE_CHUNKS, AES_ALG);
#ifndef USE_AESNI_CRYPTO
	_psTrace("***** AES-192 CBC *****\n");
	if ((err = psAesInit(&eCtx, iv, key, 24)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  psAesInit returned %d\n", err);
 		return err;
	}
	runTime(&eCtx, TINY_CHUNKS, AES_ALG);
	runTime(&eCtx, SMALL_CHUNKS, AES_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, AES_ALG);
	runTime(&eCtx, LARGE_CHUNKS, AES_ALG);
	runTime(&eCtx, HUGE_CHUNKS, AES_ALG);
#endif
	_psTrace("***** AES-256 CBC *****\n");
	if ((err = psAesInit(&eCtx, iv, key, 32)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  psAesInit returned %d\n", err);
 		return err;
	}
	runTime(&eCtx, TINY_CHUNKS, AES_ALG);
	runTime(&eCtx, SMALL_CHUNKS, AES_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, AES_ALG);
	runTime(&eCtx, LARGE_CHUNKS, AES_ALG);
	runTime(&eCtx, HUGE_CHUNKS, AES_ALG);

	return 0;
}

#ifdef USE_AES_GCM
int32 psAesTestGCM(void)
{
	int32				err;
	psCipherContext_t	eCtx;


	_psTrace("***** AES-GCM-128 *****\n");
	if ((err = psAesInitGCM(&eCtx, key, 16)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  psAesInitGCM returned %d\n", err);
 		return err;
	}
	psAesReadyGCM(&eCtx, iv, iv, 16);
	runTime(&eCtx, TINY_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, SMALL_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, LARGE_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, HUGE_CHUNKS, AES_GCM_ALG);

	_psTrace("***** AES-GCM-256 *****\n");
	if ((err = psAesInitGCM(&eCtx, key, 32)) != PS_SUCCESS) {
		_psTraceInt("FAILED:  psAesInitGCM returned %d\n", err);
 		return err;
	}
	psAesReadyGCM(&eCtx, iv, iv, 16);
	runTime(&eCtx, TINY_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, SMALL_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, LARGE_CHUNKS, AES_GCM_ALG);
	runTime(&eCtx, HUGE_CHUNKS, AES_GCM_ALG);

	return PS_SUCCESS;
}
#endif /* USE_AES_GCM */

#endif /* USE_AES */

/******************************************************************************/
#ifdef USE_3DES
int32 psDes3Test(void)
{
	psCipherContext_t	eCtx;

#ifndef PS_3DES_IMPROVE_PERF_INCREASE_CODESIZE
	_psTrace("##########\n#\n# ");
	_psTrace("3DES speeds can be improved by enabling\n# ");
	_psTrace("PS_3DES_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
	_psTrace("#\n#\n#########\n");
#endif

	psDes3Init(&eCtx, iv, key, 24);

	runTime(&eCtx, TINY_CHUNKS, DES3_ALG);
	runTime(&eCtx, SMALL_CHUNKS, DES3_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, DES3_ALG);
	runTime(&eCtx, LARGE_CHUNKS, DES3_ALG);
	runTime(&eCtx, HUGE_CHUNKS, DES3_ALG);
	return 0;
}
#endif /* USE_3DES */
/******************************************************************************/

#ifdef USE_ARC4
int32 psArc4Test(void)
{
	psCipherContext_t	eCtx;

	psArc4Init(&eCtx, key, 16);

	runTime(&eCtx, TINY_CHUNKS, ARC4_ALG);
	runTime(&eCtx, SMALL_CHUNKS, ARC4_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, ARC4_ALG);
	runTime(&eCtx, LARGE_CHUNKS, ARC4_ALG);
	runTime(&eCtx, HUGE_CHUNKS, ARC4_ALG);

	return 0;
}
#endif /* USE_ARC4 */


/******************************************************************************/
#ifdef USE_SEED
int32 psSeedTest(void)
{
	psCipherContext_t	eCtx;

	psSeedInit(&eCtx, iv, key, 16);

	runTime(&eCtx, TINY_CHUNKS, SEED_ALG);
	runTime(&eCtx, SMALL_CHUNKS, SEED_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, SEED_ALG);
	runTime(&eCtx, LARGE_CHUNKS, SEED_ALG);
	runTime(&eCtx, HUGE_CHUNKS, SEED_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SEED */
/******************************************************************************/
#ifdef USE_IDEA
int32 psIdeaTest(void)
{
	psCipherContext_t	eCtx;

	psIdeaInit(&eCtx, iv, key, 16);

	runTime(&eCtx, TINY_CHUNKS, IDEA_ALG);
	runTime(&eCtx, SMALL_CHUNKS, IDEA_ALG);
	runTime(&eCtx, MEDIUM_CHUNKS, IDEA_ALG);
	runTime(&eCtx, LARGE_CHUNKS, IDEA_ALG);
	runTime(&eCtx, HUGE_CHUNKS, IDEA_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SEED */
/******************************************************************************/

void runDigestTime(psDigestContext_t *ctx, int32 chunk, int32 alg)
{
	psTime_t			start, end;
	unsigned char		*dataChunk;
	unsigned char		hashout[64];
	int32				bytesSent, bytesToSend, round;
#ifdef USE_HIGHRES_TIME
	int32				mod;
	int64				diffu;
#else
	int32				diffm;
#endif

	dataChunk = psMalloc(NULL, chunk);
	bytesToSend = (DATABYTES_AMOUNT / chunk) * chunk;
	bytesSent = 0;

	if (alg == SHA1_ALG) {
#ifdef USE_SHA1
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha1Update(ctx, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha1Final(ctx, hashout);
		psGetTime(&end, NULL);
#endif
#ifdef USE_SHA224
	} else if (alg == SHA224_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha224Update(ctx, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha224Final(ctx, hashout);
		psGetTime(&end, NULL);
#endif
#ifdef USE_SHA256
	} else if (alg == SHA256_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha256Update(ctx, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha256Final(ctx, hashout);
		psGetTime(&end, NULL);
#endif
#ifdef USE_SHA384
	} else if (alg == SHA384_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha384Update(ctx, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha384Final(ctx, hashout);
		psGetTime(&end, NULL);
#endif
#ifdef USE_SHA512
	} else if (alg == SHA512_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psSha512Update(ctx, dataChunk, chunk);
			bytesSent += chunk;
		}
		psSha512Final(ctx, hashout);
		psGetTime(&end, NULL);
#endif
#ifdef USE_MD5
	} else if (alg == MD5_ALG) {
		psGetTime(&start, NULL);
		while (bytesSent < bytesToSend) {
			psMd5Update(ctx, dataChunk, chunk);
			bytesSent += chunk;
		}
		psMd5Final(ctx, hashout);
		psGetTime(&end, NULL);
#endif
	} else {
		return;
	}

#ifdef USE_HIGHRES_TIME
	diffu = psDiffUsecs(start, end);
	round = (bytesToSend / diffu);
	mod = (bytesToSend % diffu);
	printf("%d byte chunks in %lld usecs total for rate of %d.%d MB/sec\n",
		chunk, diffu, round, mod);
#else
	diffm = psDiffMsecs(start, end, NULL);
	round = (bytesToSend / diffm) / 1000;
	printf("%d byte chunks in %d msecs total for rate of %d MB/sec\n",
		chunk, diffm, round);
#endif

}


/******************************************************************************/
#ifdef USE_SHA1
#ifndef PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE
static int sha1faster = 1;
#else
static int sha1faster = 0;
#endif
int32  psSha1Test(void)
{
	psDigestContext_t	ctx;

	if (sha1faster) {
		_psTrace("##########\n#\n# ");
		_psTrace("SHA-1 speeds can be improved by enabling\n# ");
		_psTrace("PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
		_psTrace("#\n#\n#########\n");
	}

	psSha1Init(&ctx);
	runDigestTime(&ctx, TINY_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA1_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA1_ALG);

	return PS_SUCCESS;
}

#endif /* USE_SHA1 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_SHA256
#ifndef PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE
static int sha256faster = 1;
#else
static int sha256faster = 0;
#endif
int32 psSha256Test(void)
{
	psDigestContext_t	ctx;

	if (sha256faster) {
		_psTrace("##########\n#\n# ");
		_psTrace("SHA-256 speeds can be improved by enabling\n# ");
		_psTrace("PS_SHA256_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
		_psTrace("#\n#\n#########\n");
	}

	psSha256Init(&ctx);
	runDigestTime(&ctx, TINY_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA256_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA256_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SHA256 */
/******************************************************************************/

#ifdef USE_SHA224
int32 psSha224Test(void)
{
	psDigestContext_t	ctx;

	psSha224Init(&ctx);
	runDigestTime(&ctx, TINY_CHUNKS, SHA224_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA224_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA224_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA224_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA224_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SHA224 */

#ifdef USE_SHA384
int32 psSha384Test(void)
{
	psDigestContext_t	ctx;

	psSha384Init(&ctx);
	runDigestTime(&ctx, TINY_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA384_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA384_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SHA384 */


#ifdef USE_SHA512
#ifndef PS_SHA512_IMPROVE_PERF_INCREASE_CODESIZE
static int sha512faster = 1;
#else
static int sha512faster = 0;
#endif
int32  psSha512Test(void)
{
	psDigestContext_t	ctx;

	if (sha512faster) {
		_psTrace("##########\n#\n# ");
		_psTrace("SHA-512 speeds MIGHT improve by enabling\n# ");
		_psTrace("PS_SHA512_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
		_psTrace("#\n#\n#########\n");
	}

	psSha512Init(&ctx);
	runDigestTime(&ctx, TINY_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, SHA512_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, SHA512_ALG);

	return PS_SUCCESS;
}
#endif /* USE_SHA512 */


/******************************************************************************/
#ifdef USE_MD5
#ifndef PS_MD5_IMPROVE_PERF_INCREASE_CODESIZE
static int md5faster = 1;
#else
static int md5faster = 0;
#endif
int32 psMd5Test(void)
{
	psDigestContext_t	ctx;

	if (md5faster) {
		_psTrace("##########\n#\n# ");
		_psTrace("MD5 speeds can be improved by enabling\n# ");
		_psTrace("PS_MD5_IMPROVE_PERF_INCREASE_CODESIZE in cryptoConfig.h\n");
		_psTrace("#\n#\n#########\n");
	}

	psMd5Init(&ctx);
	runDigestTime(&ctx, TINY_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, SMALL_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, MEDIUM_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, LARGE_CHUNKS, MD5_ALG);
	runDigestTime(&ctx, HUGE_CHUNKS, MD5_ALG);

	return PS_SUCCESS;
}
#endif /* USE_MD5 */
/******************************************************************************/

/******************************************************************************/
#ifdef  USE_MD4
int32 psMd4Test(void)
{
	return PS_SUCCESS;
}
#endif /* USE_MD4 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD2
int32 psMd2Test(void)
{
	return PS_SUCCESS;
}
#endif /* USE_MD2 */
/******************************************************************************/

/******************************************************************************/

typedef struct {
	int32	(*fn)(void);
	char	name[64];
} test_t;

static test_t tests[] = {
#ifdef USE_AES
{psAesTestCBC, "***** AES-CBC TESTS *****"},
#ifdef USE_AES_GCM
{psAesTestGCM, "***** AES-GCM TESTS *****"},
#endif
#else
{NULL, "AES"},
#endif

#ifdef USE_3DES
{psDes3Test
#else
{NULL
#endif
, "***** 3DES TESTS *****"},

#ifdef USE_SEED
{psSeedTest
#else
{NULL
#endif
, "***** SEED TESTS *****"},

#ifdef USE_IDEA
{psIdeaTest
#else
{NULL
#endif
, "***** IDEA TESTS *****"},

#ifdef USE_ARC4
{psArc4Test
#else
{NULL
#endif
, "***** RC4 TESTS *****"},


#ifdef USE_SHA1
{psSha1Test
#else
{NULL
#endif
, "***** SHA1 TESTS *****"},

#ifdef USE_SHA256
{psSha256Test
#else
{NULL
#endif
, "***** SHA256 TESTS *****"},

#ifdef USE_SHA224
{psSha224Test
#else
{NULL
#endif
, "***** SHA224 TESTS *****"},

#ifdef USE_SHA384
{psSha384Test
#else
{NULL
#endif
, "***** SHA384 TESTS *****"},

#ifdef USE_SHA512
{psSha512Test
#else
{NULL
#endif
, "***** SHA512 TESTS *****"},

#ifdef USE_MD5
{psMd5Test
#else
{NULL
#endif
, "***** MD5 TESTS *****"},

#ifdef USE_MD4
{psMd4Test
#else
{NULL
#endif
, "***** MD4 TESTS *****"},

#ifdef USE_MD2
{psMd2Test
#else
{NULL
#endif
, "***** MD2 TESTS *****"},

{NULL, ""}
};

/******************************************************************************/
/*
	Main
*/

int main(int argc, char **argv)
{
	int32		i;

	if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS) {
		_psTrace("Failed to initialize library:  psCryptoOpen failed\n");
		return -1;
	}

	for (i = 0; *tests[i].name; i++) {
		if (tests[i].fn) {
			_psTraceStr("%s\n", tests[i].name);
			tests[i].fn();
		} else {
			_psTraceStr("%s: SKIPPED\n", tests[i].name);
		}
	}
	psCryptoClose();

#ifdef WIN32
	_psTrace("Press any key to close");
	getchar();
#endif

	return 0;
}

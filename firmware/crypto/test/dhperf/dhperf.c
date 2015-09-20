/**
 *	@file    dhperf.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	DH performance testing	.
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

#ifdef USE_DH

/* OPS TO PERFORM */
#define DO_GEN_INTS
#define DO_GEN_SECRET

/* DH SIZES */
//#define DO_512 /* No longer allowed in library */
#define DO_1024
#define DO_2048

/* NUMBER OF OPERATIONS */
#define ITER 30

#include "crypto/cryptoApi.h"

#define PS_OH sizeof(psPool_t)

/*
	Tuned to smallest K for each key size and optimization setting
*/
#ifdef PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#define POOL_GEN_SECRET_512		(2 * 1024) + PS_OH
#define POOL_GEN_INTS_512		(2 * 1024) + PS_OH
#define POOL_MISC_512			(2 * 1024) + PS_OH

#define POOL_GEN_SECRET_1024	(3 * 1024) + PS_OH
#define POOL_GEN_INTS_1024		(3 * 1024) + PS_OH
#define POOL_MISC_1024			(4 * 1024) + PS_OH

#define POOL_GEN_SECRET_2048	(5 * 1024) + PS_OH
#define POOL_GEN_INTS_2048		(5 * 1024) + PS_OH
#define POOL_MISC_2048			(7 * 1024) + PS_OH
#else /* PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED */
#define POOL_GEN_SECRET_512		(4 * 1024) + PS_OH
#define POOL_GEN_INTS_512		(4 * 1024) + PS_OH
#define POOL_MISC_512			(4 * 1024) + PS_OH

#define POOL_GEN_SECRET_1024	(6 * 1024) + PS_OH
#define POOL_GEN_INTS_1024		(6 * 1024) + PS_OH
#define POOL_MISC_1024			(7 * 1024) + PS_OH

#define POOL_GEN_SECRET_2048	(11 * 1024) + PS_OH
#define POOL_GEN_INTS_2048		(11 * 1024) + PS_OH
#define POOL_MISC_2048			(13 * 1024) + PS_OH
#endif

#ifdef DO_512
#include "sampleCerts/dh512.h"
#endif
#ifdef DO_1024
#include "sampleCerts/dh1024.h"
#endif
#ifdef DO_2048
#include "sampleCerts/dh2048.h"
#endif

typedef struct {
	char				*name;
	unsigned char		*key;
	uint32				len;
	int32				iter;
	int32				poolSecret;
	int32				poolInts;
	int32				poolMisc;
} keyList_t;

#ifdef USE_HIGHRES_TIME
  #define psDiffMsecs(A, B) psDiffUsecs(A, B)
  #define TIME_UNITS "    %lld usecs"
#else
  #define TIME_UNITS "    %d msecs"
#endif

/*
	Add an iteration count so we don't have to run the large keys so many times
*/
static keyList_t keys[] = {
#ifdef DO_512
	{"dh512", dhParamBuf512, sizeof(dhParamBuf512), ITER, POOL_GEN_SECRET_512,
		POOL_GEN_INTS_512, POOL_MISC_512},
#endif
#ifdef DO_1024
	{"dh1024", dhParamBuf1024, sizeof(dhParamBuf1024), ITER,
		POOL_GEN_SECRET_1024, POOL_GEN_INTS_1024, POOL_MISC_1024},
#endif
#ifdef DO_2048
	{"dh2048", dhParamBuf2048, sizeof(dhParamBuf2048), ITER,
		POOL_GEN_SECRET_2048, POOL_GEN_INTS_2048, POOL_MISC_2048},
#endif
	{NULL, NULL, 0, 0, 0, 0}
};

/******************************************************************************/
/*
	Main
*/


int main(int argc, char **argv)
{
	psPool_t		*pool, *misc;
	psDhParams_t	*dhParams;
	psDhKey_t		dhKeyPriv, dhKeyPub;
	uint32			pLen, gLen;
	unsigned char	*p, *g;
	psTime_t		start, end;
	uint32			iter, i = 0;
	unsigned char	out[256];
	uint32			outLen = 256;

	pool = misc = NULL;
	if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS) {
		_psTrace("Failed to initialize library:  psCryptoOpen failed\n");
		return -1;
	}
	_psTraceStr("STARTING DHPERF\n", NULL);

	while (keys[i].key != NULL) {
		_psTraceStr("Test %s...\n", keys[i].name);
		pkcs3ParseDhParamBin(misc, (unsigned char*)keys[i].key,	keys[i].len,
			&dhParams);

		iter = 0;

#ifdef DO_GEN_INTS
		psGetTime(&start, NULL);
		while (iter < keys[i].iter) {
			if (psDhKeyGenInts(pool, dhParams->size, &dhParams->p, &dhParams->g,
					&dhKeyPriv, NULL) < 0) {
				_psTrace("	FAILED OPERATION\n");
			}

			psDhFreeKey(&dhKeyPriv);
			iter++;
		}
		psGetTime(&end, NULL);
		_psTraceInt(TIME_UNITS " genInts\n", psDiffMsecs(start, end, NULL));
#endif /* DO_GEN_INTS */

#ifdef DO_GEN_SECRET
/*
		GenSecret
*/
		psDhExportParameters(misc, dhParams, &pLen, &p, &gLen, &g);
		if (psDhKeyGenInts(misc, dhParams->size, &dhParams->p, &dhParams->g,
				&dhKeyPriv, NULL) < 0) {
			_psTrace("	FAILED OPERATION\n");
		}
		if (psDhKeyGenInts(misc, dhParams->size, &dhParams->p, &dhParams->g,
				&dhKeyPub, NULL) < 0) {
			_psTrace("	FAILED OPERATION\n");
		}
		iter = 0;
		outLen = 256;
		psGetTime(&start, NULL);
		while (iter < keys[i].iter) {
			if (psDhGenSecret(pool, &dhKeyPriv, &dhKeyPub, p, pLen,
					out, &outLen, NULL) < 0) {
				_psTrace("	FAILED OPERATION\n");
			}

			iter++;
		}
		psGetTime(&end, NULL);
		psDhFreeKey(&dhKeyPriv);
		psDhFreeKey(&dhKeyPub);
		_psTraceInt(TIME_UNITS " genSecret\n", psDiffMsecs(start, end, NULL));
#endif /* DO_GEN_SECRET */

		psFree(p, misc);
		psFree(g, misc);
		pkcs3FreeDhParams(dhParams);
		i++;
	}

#ifdef WIN32
	_psTrace("Press any key to close");
	getchar();
#endif
	_psTraceStr("FINISHED DHPERF\n", NULL);
	psCryptoClose();
	return 0;
}

#else

/* Stub main */
#include <stdio.h>

int main(int argc, char **argv) {
	printf("USE_DH not defined.\n");
	return 0;
}

#endif /* USE_DH */


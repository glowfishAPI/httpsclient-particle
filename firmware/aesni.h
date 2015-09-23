/**
 *	@file    aesni.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Header for AES-NI Hardware Crypto Instructions.
 */
/*
 *	Copyright (c) 2014-2015 INSIDE Secure Corporation
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

#include "cryptoApi.h"

#ifndef _h_PS_AESNI_CRYPTO
#define _h_PS_AESNI_CRYPTO

#ifdef USE_AESNI_CRYPTO
/*
	Intel Native Instructions for AES
	http://en.wikipedia.org/wiki/AES_instruction_set
 */
/******************************************************************************/

#ifdef USE_AES_CBC_EXTERNAL

#include <stdio.h>
#include <emmintrin.h>

/*
	Our usage in SSL is that any given key is used only for either encryption
	or decryption, not both. If the same key is to be used for both, two
	key structures must be initialized.
	The first use of the key is what marks the key's usage (for example if
	psAesEncryptBlock() is called on the key first, it can only be used
	in future calls to encrypt.
*/
typedef enum {
	AES_UNDEFINED = 0,
	AES_ENCRYPT,
	AES_DECRYPT
} keyType_e;

typedef struct {
	__m128i		skey[15];	/* Key schedule (encrypt or decrypt) */
	int32		rounds;
	keyType_e	type;		/* Encrypt or Decrypt */
} psAesKey_t;

typedef struct {
	int32			blocklen;
	unsigned char	IV[16];
	int32			keylen;
	psAesKey_t		key;
#ifdef USE_AES_GCM_EXTERNAL
	__m128i h_m128i;
	__m128i y_m128i;
	__m128i icb_m128i;
	int cipher_started;
	unsigned int a_len;
	unsigned int c_len;
#endif
} psAesCipher_t;

#endif /* USE_AES_CBC_EXTERNAL */

/******************************************************************************/

#endif /* USE_AESNI_CRYPTO */
#endif /* _h_PS_AESNI_CRYPTO */
/******************************************************************************/

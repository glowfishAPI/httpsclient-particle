/**
 *	@file    memset_s.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Secure memset api that will not be optimized out by compiler.
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
/**
    Use volatile ref to s[] to tell compiler to keep function around.
    This file also should only be compiled with -O0.
*/

#if !defined(_WIN32) && !defined(__APPLE__)

#include <string.h>

typedef size_t rsize_t;
typedef int errno_t;

#pragma GCC push_options
#pragma GCC optimize("O0")
errno_t __attribute__((optimize("O0"))) memset_s(void *s, rsize_t smax,
	int c, rsize_t n)
{
	if (n > smax) {
		n = smax;
	}
	memset(s, c, n);
	return ((unsigned char volatile *)s)[0];
}
#pragma GCC pop_options
#endif /* !WIN && ! APPLE */

/******************************************************************************/

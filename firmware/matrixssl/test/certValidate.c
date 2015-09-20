/**
 *	@file    certValidate.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Standalone certificate parsing and chain validation test.
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

#include "matrixssl/matrixsslApi.h"

/****************************** Local Functions *******************************/

#ifndef USE_ONLY_PSK_CIPHER_SUITE

static void usage(void)
{
	printf("usage: certValidate <rootcert> <certchain> <expectedsubject>\n"
	"    <rootcert>  PEM file containing one or more trusted root certs\n"
	"                If specified as NULL, no root certs will be loaded\n"
	"    <certchain> PEM file containing cert chain to validate\n"
	"    <subject>   Name (usually DNS name) to match to certchain subject\n"
	"                If specified as NULL, subject will not be validated\n"
);
}

static char *flagstostr(int flags)
{
	static char f[80];	/* Not reentrant, but good enough for this test */
	char *s = f;

	if (flags) {
		s += sprintf(s, " (");
		if (flags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG) {
			s += sprintf(s, "KEY_USAGE ");
		}
		if (flags & PS_CERT_AUTH_FAIL_EKU_FLAG) {
			s += sprintf(s, "EXTENDED_KEY_USAGE ");
		}
		if (flags & PS_CERT_AUTH_FAIL_SUBJECT_FLAG) {
			s += sprintf(s, "SUBJECT ");
		}
		if (flags & PS_CERT_AUTH_FAIL_DATE_FLAG) {
			s += sprintf(s, "DATE ");
		}
		s += sprintf(s, ")");
		return f;
	}
	return "";
}

static char *errtostr(int rc)
{
	static char e[80];	/* Not reentrant, but good enough for this test */

	switch (rc) {
	case 0:
	case PS_CERT_AUTH_PASS:
		return "PASS";
	break;
	case PS_CERT_AUTH_FAIL_BC:
		return "FAIL Basic Constraints";
	break;
	case PS_CERT_AUTH_FAIL_DN:
		return "FAIL Distinguished Name Match";
	break;
	case PS_CERT_AUTH_FAIL_SIG:
		return "FAIL Signature Validation";
	break;
	case PS_CERT_AUTH_FAIL_REVOKED:
		return "FAIL Certificate Revoked";
	break;
	case PS_CERT_AUTH_FAIL:
		return "FAIL Authentication Fail";
	break;
	case PS_CERT_AUTH_FAIL_EXTENSION:
		return "FAIL Extension";
	break;
	case PS_CERT_AUTH_FAIL_PATH_LEN:
		return "FAIL Path Length";
	break;
	case PS_CERT_AUTH_FAIL_AUTHKEY:
		return "FAIL Auth Key / Subject Key Match";
	break;
	default:
		sprintf(e, "FAIL %d", rc);
		return e;
	}
}

/******************************************************************************/
/*
	Certificate validation test
 */
int32 main(int32 argc, char **argv)
{
	psX509Cert_t	*trusted, *chain, *cert;
	psPool_t		*pool;
	int32			rc, i;
	uint32			faildate, flags, depth;

	rc = -1;
	faildate = 0;
	pool = NULL;
	trusted = chain = NULL;

	if (argc != 4) {
		usage();
		return -1;
	}

	if ((rc = matrixSslOpen()) < 0) {
		_psTrace("MatrixSSL library init failure.  Exiting\n");
		return rc;
	}

	if (strcmp(argv[1], "NULL") != 0) {
		if ((rc = psX509ParseCertFile(pool, argv[1], &trusted, 0)) < 0) {
			if (rc == PS_PLATFORM_FAIL) {
				printf("FAIL open file %s %d\n", argv[1], rc);
			} else {
				printf("FAIL parse %s %d\n", argv[1], rc);
			}
			goto L_EXIT;
		}
		printf("  Loaded root file %s\n", argv[1]);
		for (cert = trusted, i = 0; cert != NULL; cert = cert->next, i++) {
			printf("    [%d]:%s\n", i, cert->subject.commonName);
			psAssert(cert->authStatus == 0);
			faildate |= cert->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG;
			psAssert((cert->authFailFlags & ~faildate) == 0);
		}
	}

	if ((rc = psX509ParseCertFile(pool, argv[2], &chain, 0)) < 0) {
		if (rc == PS_PLATFORM_FAIL) {
			printf("FAIL open file %s %d\n", argv[2], rc);
		} else {
			printf("FAIL parse %s %d\n", argv[2], rc);
		}
		goto L_EXIT;
	}
	printf("  Loaded chain file %s\n", argv[2]);
	for (cert = chain, i = 0; cert != NULL; cert = cert->next, i++) {
		printf("    [%d]:%s\n", i, cert->subject.commonName);
		psAssert(cert->authStatus == 0);
		faildate |= cert->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG;
		psAssert((cert->authFailFlags & ~faildate) == 0);
	}

	if (strcmp(argv[3], "NULL") != 0) {
		if (psX509ValidateGeneralName(argv[3]) < 0) {
			printf("FAIL validate general name %s\n", argv[3]);
			goto L_EXIT;
		}
		rc = matrixValidateCerts(pool, chain, trusted, argv[3], &cert, NULL,
			NULL);
	} else {
		printf("WARN subject not validated\n");
		rc = matrixValidateCerts(pool, chain, trusted, NULL, &cert, NULL, NULL);
	}
	if (rc < 0) {
		printf("%s\n", errtostr(rc));
		for (cert = chain, i = 0; cert != NULL; cert = cert->next, i++) {
			printf("  Validate:%s[%d]:%s FAIL %d, status=%d, flags=%u\n",
				argv[2], i, cert->subject.commonName, rc,
				cert->authStatus, cert->authFailFlags);
			if (cert->authStatus != PS_CERT_AUTH_PASS) {
				printf("    authStatus %s\n", errtostr(cert->authStatus));
			}
			if (cert->authFailFlags) {
				printf("    authFailFlags %s\n", flagstostr(cert->authFailFlags));
			}
		}
		goto L_EXIT;
	}
	/* If faildate is set and we don't have an error in rc... */
	psAssert(faildate == 0);

	flags = depth = 0;
	printf("  Validate %s:%s rc %d\n", argv[2], cert->subject.commonName, rc);
	for (cert = chain, i = 0; cert != NULL; cert = cert->next, i++) {
		printf("    [%d] authStatus=%d, authFailFlags=%u\n",
			i, cert->authStatus, cert->authFailFlags);
		if (cert->authStatus != PS_CERT_AUTH_PASS) {
			depth = i;
			rc = cert->authStatus;
			flags |= cert->authFailFlags;
		} else {
			psAssert(cert->authFailFlags == 0);
		}
	}
	if (rc < 0) {
		printf("%s%s in %s[%d]\n", errtostr(rc), flagstostr(flags),
			argv[2], depth);
		goto L_EXIT;
	}
	printf("PASS\n");
	rc = 0;

L_EXIT:
	if (trusted) psX509FreeCert(trusted);
	if (chain) psX509FreeCert(chain);
	matrixSslClose();

	return rc;
}

#else

int32 main(int32 argc, char **argv)
{
	printf("Not applicable when USE_ONLY_PSK_CIPHER_SUITE defined\n");
	return 0;
}

#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/


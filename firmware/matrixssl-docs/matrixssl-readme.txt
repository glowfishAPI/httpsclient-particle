MatrixSSL Directory Structure

matrixssl/
	This directory contains files the implement the SSL and TLS protocol.
	test/
		Single-process SSL handshake test application that exercises the
		cipher suites and handshakes that are available in the currently
		built library

core/
	Pool based malloc() implementation*
	Utility functions
	POSIX/
		Operating system layer for Linux, BSD
		TCP layer for Linux, BSD and Windows
	WIN32/
		Operating system layer for Windows NT, 2K, XP, Vista, 7

crypto/
	digest/
		Message digests: md5, sha-1, sha-256*, hmac, etc.
	keyformat/
		Key parsing routines for x.509, base64 and asn.1 data formats
	math/
		Large integer math operations
	prng/
		Psuedo random number generation
	pubkey/
		RSA and DH* operations
		PKCS enccoding and decoding of keys
	symmetric/
		Symmetric ciphers: arc4, 3des, aes, seed*
	hardware/
		AES-NI 
		Platform specific hardware crypto* 

apps/
	Example SSL client using blocking sockets and session resumption
	Example SSL server using non-blocking sockets and simultaneous connections

doc/
	Release notes
	Developer guides
	API documentation

sampleCerts/
	Sample RSA and EC* keys and certificate files for testing and example apps

validation_tests/
	Comprehensive tests that compile numerous configurations of servers and
	clients and are then run with the various supported ciphers suites and
	protocol versions. 

* utilities/ 
	certgen - generate X.509 cert from a certificate request or self-signed
	certrequest - generate a cert request from a private RSA key
	pemtomem - convert a pem format key or certificate to C header
	rsakeygen - generate an RSA public/private keypair


* commercial licensed version only

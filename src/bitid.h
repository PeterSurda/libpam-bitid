#ifndef PAM_BITID_BITID_H
#define PAM_BITID_BITID_H
#include <qrencode.h>

#define NONCE_LEN 16

struct response {
	char *address;
	char *signature;
	char *uri;
	int gotresponse;
};

struct authstruct {
	const char *file;
	struct response termresp;
	struct response httpresp;
	char *challenge;
	char *challengeuri;
	QRcode *qrcode;
	int doqr;
	int port;
	int port_lo;
	int port_hi;
	const char *hostname;
};

extern struct authstruct auth;

#endif

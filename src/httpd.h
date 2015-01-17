#ifndef PAM_BITID_HTTPD_H
#define PAM_BITID_HTTPD_H
#include "qr.h"

#define POSTBUFFERSIZE 8192
#define HTTP_POST_ENCODING_APPLICATION_JSON "application/json"

enum uri_type {
	HTTP,
	BITID
};

struct connection_info_struct {
	int has_upload;
	int length;
	int offset;
	char *data;
	int is_response;
};

struct connection_info_struct * init_coninfo();
char * builduri(char *hostname, int port, char *nonce, enum uri_type type);
int bitid_callback(void * cls,
	struct MHD_Connection * connection,
	const char * url,
	const char * method,
	const char * version,
	const char * upload_data,
	size_t * upload_data_size,
	void ** con_cls);

void http_connection_closed (void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe);

#endif

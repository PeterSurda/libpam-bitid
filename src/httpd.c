#define _GNU_SOURCE
#include <features.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <microhttpd.h>


#include "httpd.h"
#include "json.h"
#include "png.h"

static const char *okresponse = "<html><body>All ok.</body></html>";
static const char *failresponse = "<html><body>Fail.</body></html>";

struct connection_info_struct * init_coninfo()
{
	struct connection_info_struct *con_info;

	if ((con_info = malloc(sizeof (struct connection_info_struct))) == NULL)
		return (NULL);

	con_info->has_upload = 0;
	con_info->length = 0;
	con_info->offset = 0;
	con_info->is_response = 0;
	con_info->data = NULL;

	return (con_info);
}

char * builduri(char *hostname, int port, char *nonce, enum uri_type type)
{
	char *out = calloc(1024, sizeof(char)); // FIXME proper length crap
	if (out == NULL)
		return NULL;
	if (type == HTTP)
		snprintf (out, 1023, "http%s://%s:%i/callback?x=%s&u=1", (port == 443 ? "s" : ""), hostname, port, nonce);
	else
		snprintf (out, 1023, "bitid://%s:%i/callback?x=%s&u=1", hostname, port, nonce);
	return out;
}

int bitid_callback(void * cls,
	struct MHD_Connection * connection,
	const char * url,
	const char * method,
	const char * version,
	const char * upload_data,
	size_t * upload_data_size,
	void ** con_cls) {
	static struct png_stream * png;
	struct MHD_Response * response;
	int ret;

	if (*con_cls == NULL) {
		//fprintf (stderr, "Connection init\n");
		struct connection_info_struct *con_info;
		if (0 != strcmp(method, MHD_HTTP_METHOD_GET) && 0 != strcmp(method, MHD_HTTP_METHOD_POST)) {
			//fprintf (stderr, "Unsupported method %s\n", method);
			return MHD_NO; /* unexpected method */
		}
		if ((con_info = init_coninfo()) == NULL) {
			//fprintf (stderr, "init_coninfo failed\n");
			return MHD_NO;
		}
		
		if (!strcmp (method, MHD_HTTP_METHOD_POST)) {
			con_info->has_upload = 1;
			const char *lenstr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_LENGTH);
			con_info->length = atoi(lenstr);
			if (con_info->length >= POSTBUFFERSIZE) {
				free(con_info);
				//fprintf (stderr, "Too long post\n");
				return (MHD_NO);
			}
			//fprintf (stderr, "Creating data buffer\n");
			con_info->data = calloc (con_info->length, sizeof(char));
			if (!con_info->data) {
				free(con_info);
				//fprintf (stderr, "Failed to allocate memory\n");
				return (MHD_NO);
			}
			//fprintf (stderr, "Created data buffer\n");
		}
		*con_cls = (void *)con_info;
		return (MHD_YES);
	} 
	if (!strcmp (method, MHD_HTTP_METHOD_POST)) {
		//fprintf (stderr, "Processing post chunk of %ib\n", (int) *upload_data_size);
		struct connection_info_struct *con_info = (struct connection_info_struct *)*con_cls;
		if (*upload_data_size != 0) {
			if (*upload_data_size + con_info->offset >= POSTBUFFERSIZE || *upload_data_size + con_info->offset > con_info->length) {
				// TODO free stuff
				//fprintf (stderr, "Too much data (%i at %i of %i)\n", (int) *upload_data_size, con_info->offset, con_info->length);
				return MHD_NO;
			}
			memcpy(con_info->data + con_info->offset, upload_data, (size_t) *upload_data_size);
			con_info->offset += *upload_data_size;
			*upload_data_size = 0;
		} else {
			// done
		//if (con_info->offset >= con_info->length) {
			//MHD_set_connection_value(connection, MHD_RESPONSE_HEADER_KIND, "Content-Type", "text/plain");
			if (!decode_json_data(con_info->data, con_info->offset)) {
				con_info->is_response = 1;
				response = MHD_create_response_from_buffer(strlen(okresponse),
					(void*) okresponse, MHD_RESPMEM_PERSISTENT);
			} else {
				response = MHD_create_response_from_buffer(strlen(failresponse),
					(void*) failresponse, MHD_RESPMEM_PERSISTENT);
			}
			//auth.signature = calloc (strlen(url) + 1, sizeof(char));
			//strncpy(auth.signature, url, strlen(url));
			MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");
			ret = MHD_queue_response(connection,
				MHD_HTTP_OK,
				response);
			MHD_destroy_response(response);
		}
		return (MHD_YES);
	} else { // GET
		//fprintf (stderr, "Processing get\n");
		//MHD_set_connection_value(connection, MHD_RESPONSE_HEADER_KIND, "Content-Type", "image/png");
		png = png_write((const QRcode *) auth.qrcode, PNG_TYPE);
		response = MHD_create_response_from_buffer(png->stream_len,
			(void*) png->stream_ptr, MHD_RESPMEM_MUST_COPY);
		MHD_add_response_header (response, MHD_HTTP_HEADER_CONTENT_TYPE, "image/png");
		ret = MHD_queue_response(connection,
			MHD_HTTP_OK,
			response);
		MHD_destroy_response(response);
		free(png->stream_ptr);
		free(png);
		return (MHD_YES);
	}
	return ret;
}

void http_connection_closed (void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
	struct connection_info_struct *con_info = (struct connection_info_struct *)*con_cls;
	if (con_info->is_response)
		auth.httpresp.gotresponse = 1;
	if (con_info->data)
		free(con_info->data);
	if (con_info)
		free(con_info);
}

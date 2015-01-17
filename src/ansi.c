#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qrencode.h>
#include <security/pam_ext.h>
#include <syslog.h>

#include "ansi.h"

static int margin = 4;

void ansi_write_margin(pam_handle_t *pamh, int realwidth,
	char* buffer, const char* white, int white_s )
{
	int y;

	strncpy(buffer, white, white_s);
	memset(buffer + white_s, ' ', realwidth * 2);
	strcpy(buffer + white_s + realwidth * 2, "\033[0m"); // reset to default colors
	for(y=0; y<margin; y++ ){
		//pam_info(pamh, "%s", buffer);
		pam_prompt(pamh, PAM_ERROR_MSG, NULL, "%s", buffer);
	}
}

int ansi_write(pam_handle_t *pamh, const QRcode *qrcode, enum imageType image_type)
{
	unsigned char *row, *p;
	int x, y;
	int realwidth;
	int last;
	int size = 1;

	margin = 1;

	const char *white, *black;
	char *buffer;
	int white_s, black_s, buffer_s;

	if(image_type == ANSI256_TYPE){
		/* codes for 256 color compatible terminals */
		white = "\033[48;5;231m";
		white_s = 11;
		black = "\033[48;5;16m";
		black_s = 10;
	} else {
		white = "\033[47m";
		white_s = 5;
		black = "\033[40m";
		black_s = 5;
	}

	realwidth = (qrcode->width + margin * 2) * size;
	buffer_s = (realwidth * white_s) * 2;
	buffer = (char *)malloc(buffer_s);
	if(buffer == NULL) {
		pam_syslog(pamh, LOG_ERR, "Failed to allocate memory.");
		return 1;
	}

	/* top margin */
	ansi_write_margin(pamh, realwidth, buffer, white, white_s);

	/* data */
	p = qrcode->data;
	for(y=0; y<qrcode->width; y++) {
		row = (p+(y*qrcode->width));

		memset(buffer, 0, buffer_s);
		strncpy(buffer, white, white_s);
		for(x=0; x<margin; x++ ){
			strncat(buffer, "  ", 2);
		}
		last = 0;

		for(x=0; x<qrcode->width; x++) {
			if(*(row+x)&0x1) {
				if( last != 1 ){
					strncat(buffer, black, black_s);
					last = 1;
				}
			} else {
				if( last != 0 ){
					strncat(buffer, white, white_s);
					last = 0;
				}
			}
			strncat(buffer, "  ", 2);
		}

		if( last != 0 ){
			strncat(buffer, white, white_s);
		}
		for(x=0; x<margin; x++ ){
			strncat(buffer, "  ", 2);
		}
		strncat(buffer, "\033[0m", 5);
		//pam_info(pamh, "%s", buffer);
		pam_prompt(pamh, PAM_ERROR_MSG, NULL, "%s", buffer);
	}

	/* bottom margin */
	ansi_write_margin(pamh, realwidth, buffer, white, white_s);

	free(buffer);

	return 0;
}

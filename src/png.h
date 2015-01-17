#ifndef PAM_BITID_PNG_H
#define PAM_BITID_PNG_H
#include <libpng12/png.h>
#include <qrencode.h>
#include "qr.h"

#define INCHES_PER_METER (100.0/2.54)

struct png_stream {
	char *stream_ptr;     /*  location to write PNG stream  */
	int stream_len;               /*  number of bytes written       */
};
void png_user_write_data(png_structp png_ptr,png_bytep data, png_uint_32 length);
void png_user_flush_data(png_structp png_ptr);
void png_fill_row(unsigned char *row, int size, const unsigned char color[]);
struct png_stream *png_write(const QRcode *qrcode, enum imageType type);

#endif

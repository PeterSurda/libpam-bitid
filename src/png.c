#include <stdlib.h>
#include "png.h"

static int margin = 4;
static unsigned char fg_color[4] = {0, 0, 0, 255};
static unsigned char bg_color[4] = {255, 255, 255, 255};

void png_user_write_data(png_structp png_ptr,png_bytep data, png_uint_32 length)
/*
        Custom write function used to that libpng will write
        to memory location instead of a file on disk
*/
{
	struct png_stream *mem;

	mem=(struct png_stream *)png_get_io_ptr(png_ptr);
	if (mem->stream_ptr == NULL) {
		mem->stream_ptr = (char *) calloc(length, sizeof(char *));
	} else {
		mem->stream_ptr = (char *) realloc(mem->stream_ptr, (mem->stream_len + length) * sizeof(char *));
	}
/*     printf("SAGwr %ld %ld %x\n",offset,length,ptr);    */
     /*for (j=offset,k=0;k<length;j++,k++) ptr[j]=data[k];*/
	memcpy(mem->stream_ptr+mem->stream_len,data,length);
	mem->stream_len += length;
}

void png_user_flush_data(png_structp png_ptr)
/*
        Dummy Custom flush function
*/
{
	return;
	//int *do_nothing=NULL;
}

void png_fill_row(unsigned char *row, int size, const unsigned char color[])
{
	int i;

	for(i = 0; i< size; i++) {
		memcpy(row, color, 4);
		row += 4;
	}
}

struct png_stream *png_write(const QRcode *qrcode, enum imageType type)
{
	png_structp png_ptr;
	png_infop info_ptr;
	png_colorp palette = NULL;
	png_byte alpha_values[2];
	struct png_stream *write_io_ptr;
	int size = 3;

	write_io_ptr = calloc(sizeof(struct png_stream), sizeof(char));

	unsigned char *row, *p, *q;
	int x, y, xx, yy, bit;
	int realwidth;

	realwidth = (qrcode->width + margin * 2) * size;
	if(type == PNG_TYPE) {
		row = (unsigned char *)malloc((realwidth + 7) / 8);
	} else if(type == PNG32_TYPE) {
		row = (unsigned char *)malloc(realwidth * 4);
	} else {
		fprintf(stderr, "Internal error.\n");
		exit(EXIT_FAILURE);
	}

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(png_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG writer.\n");
		exit(EXIT_FAILURE);
	}

	info_ptr = png_create_info_struct(png_ptr);
	if(info_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG write.\n");
		exit(EXIT_FAILURE);
	}

	if(setjmp(png_jmpbuf(png_ptr))) {
		png_destroy_write_struct(&png_ptr, &info_ptr);
		fprintf(stderr, "Failed to write PNG image.\n");
		exit(EXIT_FAILURE);
	}

	if(type == PNG_TYPE) {
		palette = (png_colorp) malloc(sizeof(png_color) * 2);
		if(palette == NULL) {
			fprintf(stderr, "Failed to allocate memory.\n");
			exit(EXIT_FAILURE);
		}
		palette[0].red   = fg_color[0];
		palette[0].green = fg_color[1];
		palette[0].blue  = fg_color[2];
		palette[1].red   = bg_color[0];
		palette[1].green = bg_color[1];
		palette[1].blue  = bg_color[2];
		alpha_values[0] = fg_color[3];
		alpha_values[1] = bg_color[3];
		png_set_PLTE(png_ptr, info_ptr, palette, 2);
		png_set_tRNS(png_ptr, info_ptr, alpha_values, 2, NULL);
	}

	/*    Initialize info for writing PNG stream to memory   */

	write_io_ptr->stream_ptr=(png_voidp)NULL;
	write_io_ptr->stream_len=0;

	png_set_write_fn(png_ptr,(png_voidp)write_io_ptr,(png_rw_ptr)png_user_write_data,
		(png_flush_ptr)png_user_flush_data);

	//png_init_io(png_ptr, fp);
	if(type == PNG_TYPE) {
		png_set_IHDR(png_ptr, info_ptr,
				realwidth, realwidth,
				1,
				PNG_COLOR_TYPE_PALETTE,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	} else {
		png_set_IHDR(png_ptr, info_ptr,
				realwidth, realwidth,
				8,
				PNG_COLOR_TYPE_RGB_ALPHA,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	}
	png_set_pHYs(png_ptr, info_ptr,
			72 * INCHES_PER_METER,
			72 * INCHES_PER_METER,
			PNG_RESOLUTION_METER);

/*
	bytes=*nbits/8;
	row_pointers=malloc((*height)*sizeof(png_bytep));
	for (j=0;j<*height;j++) row_pointers[j]=(png_bytep *)(data+(j*(*width)*bytes));
	png_set_rows(png_ptr, info_ptr, (png_bytepp)row_pointers);
*/
	png_write_info(png_ptr, info_ptr);

	if(type == PNG_TYPE) {
	/* top margin */
		memset(row, 0xff, (realwidth + 7) / 8);
		for(y=0; y<margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y=0; y<qrcode->width; y++) {
			memset(row, 0xff, (realwidth + 7) / 8);
			q = row;
			q += margin * size / 8;
			bit = 7 - (margin * size % 8);
			for(x=0; x<qrcode->width; x++) {
				for(xx=0; xx<size; xx++) {
					*q ^= (*p & 1) << bit;
					bit--;
					if(bit < 0) {
						q++;
						bit = 7;
					}
				}
				p++;
			}
			for(yy=0; yy<size; yy++) {
				png_write_row(png_ptr, row);
			}
		}
		/* bottom margin */
		memset(row, 0xff, (realwidth + 7) / 8);
		for(y=0; y<margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	} else {
	/* top margin */
		png_fill_row(row, realwidth, bg_color);
		for(y=0; y<margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y=0; y<qrcode->width; y++) {
			png_fill_row(row, realwidth, bg_color);
			for(x=0; x<qrcode->width; x++) {
				for(xx=0; xx<size; xx++) {
					if(*p & 1) {
						memcpy(&row[((margin + x) * size + xx) * 4], fg_color, 4);
					}
				}
				p++;
			}
			for(yy=0; yy<size; yy++) {
				png_write_row(png_ptr, row);
			}
		}
		/* bottom margin */
		png_fill_row(row, realwidth, bg_color);
		for(y=0; y<margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	}

	png_write_end(png_ptr, info_ptr);
	png_destroy_write_struct(&png_ptr, &info_ptr);

	free(row);
	free(palette);

	return write_io_ptr;
}

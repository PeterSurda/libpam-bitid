pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_bitid.la

noinst_HEADERS = baseX.h ansi.h crypto.h bitid.h httpd.h json.h png.h qr.h

pam_bitid_la_SOURCES = baseX.c ansi.c crypto.c bitid.c httpd.c json.c png.c pam_bitid.c
pam_bitid_la_LIBADD =  -lcrypto -lqrencode -lmicrohttpd -lpng -ljson-c
pam_bitid_la_LDFLAGS = -L/usr/lib -no-undefined -avoid-version -module
pam_bitid_la_CFLAGS = -Wall -I../include

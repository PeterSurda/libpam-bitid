#ifndef PAM_BITID_ANSI_H
#define PAM_BITID_ANSI_H
#include "qr.h"
#include <security/pam_ext.h>

void ansi_write_margin(pam_handle_t *pamh, int realwidth, char* buffer, const char* white, int white_s);
int ansi_write(pam_handle_t *pamh, const QRcode *qrcode, enum imageType image_type);
#endif

#ifndef PAM_BITID_JSON_H
#define PAM_BITID_JSON_H

#include "bitid.h"

#define JSON_RESPONSE_ADDRESS "address"
#define JSON_RESPONSE_SIGNATURE "signature"
#define JSON_RESPONSE_URI "uri"

int decode_json_data (char *data, int len);
#endif

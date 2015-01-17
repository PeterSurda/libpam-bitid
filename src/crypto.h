#ifndef PAM_BITID_CRYPTO_H
#define PAM_BITID_CRYPTO_H
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#define PUBLIC_KEY_SIZE	65
#define PUBLIC_KEY_SIZE_COMPRESSED	33
#define SIGNATURE_SIZE	65
#define BTC_BIN_ADDR_SIZE 25

int
ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, 
	const unsigned char *msg, int msglen, int recid, int check);

int
dbl_hash256(unsigned char *data_in, int data_in_len, unsigned char *data_out);

int
hash256(unsigned char *data_in, int data_in_len, unsigned char *data_out);

int
hash160(unsigned char *data_in, int data_in_len, unsigned char *data_out);

int
msg2hash256(unsigned char *msg_s, int msg_len, unsigned char *data_out);

unsigned char *
pubkey2address(EC_KEY *pubkey, int *addr_len, int compressed);

int
verified_pubkey_recovery(EC_KEY *key, ECDSA_SIG *sig, 
	unsigned char *sig_bin, int sig_bin_len, unsigned char *hash, int hash_len, int *compressed);

int
verify_signature(pam_handle_t *pamh, char *addr_s, char *msg_s, char *sign_s);

int
verify_address(char *addr_s);

#endif

#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include "crypto.h"
#include "baseX.h"

/* Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
 * recid selects which key is recovered
 * if check is non-zero, additional checks are performed
 *
 * Original source of this code from bitcoin-qt client.
 *
 * Copyright (c) 2009-2013 Bitcoin Developers
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */
int
ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, 
	const unsigned char *msg, int msglen, int recid, int check)
{
    	if (!eckey) return 0;

    	int ret = 0;
    	BN_CTX *ctx = NULL;

    	BIGNUM *x = NULL;
    	BIGNUM *e = NULL;
    	BIGNUM *order = NULL;
    	BIGNUM *sor = NULL;
    	BIGNUM *eor = NULL;
    	BIGNUM *field = NULL;
    	EC_POINT *R = NULL;
    	EC_POINT *O = NULL;
    	EC_POINT *Q = NULL;
    	BIGNUM *rr = NULL;
    	BIGNUM *zero = NULL;
    	int n = 0;
    	int i = recid / 2;

    	const EC_GROUP *group = EC_KEY_get0_group(eckey);
    	if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    	BN_CTX_start(ctx);
    	order = BN_CTX_get(ctx);
    	if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    	x = BN_CTX_get(ctx);
    	if (!BN_copy(x, order)) { ret=-1; goto err; }
    	if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    	if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
    	field = BN_CTX_get(ctx);
    	if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    	if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    	if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    	if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    	if (check) {
        	if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        	if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        	if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    	}
    	if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    	n = EC_GROUP_get_degree(group);
    	e = BN_CTX_get(ctx);
    	if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    	if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    	zero = BN_CTX_get(ctx);
    	if (!BN_zero(zero)) { ret=-1; goto err; }
    	if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    	rr = BN_CTX_get(ctx);
    	if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
    	sor = BN_CTX_get(ctx);
    	if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
    	eor = BN_CTX_get(ctx);
    	if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    	if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    	if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    	ret = 1;

err:
    	if (ctx) {
        	BN_CTX_end(ctx);
        	BN_CTX_free(ctx);
    	}
    	if (R != NULL) EC_POINT_free(R);
    	if (O != NULL) EC_POINT_free(O);
    	if (Q != NULL) EC_POINT_free(Q);
    	return ret;
}

#if 0
// https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
static int 
variable_uint_size(uint64_t i)
{
    if (i < 0xfd)
        return 1;
    else if (i <= 0xffff)
        return 3;
    else if (i <= 0xffffffff)
        return 5;
    else
        return 9;
}
#endif

/* returns a string of length SHA256_DIGEST_LENGTH in data_out */
int
dbl_hash256(unsigned char *data_in, int data_in_len, unsigned char *data_out)
{
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data_in, data_in_len);
	SHA256_Final(hash1, &ctx);
	SHA256(hash1, sizeof(hash1), data_out);
	/*
	printf("dbl_hash256(hex): ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                printf("%02x", data_out[i]);
        printf("\n");
	*/
	return 0;
}

/* returns a string of length SHA256_DIGEST_LENGTH in data_out */
int
hash256(unsigned char *data_in, int data_in_len, unsigned char *data_out)
{
	SHA256(data_in, data_in_len, data_out);
	return 0;
}

/* returns a string of length RIPEMD160_DIGEST_LENGTH in data_out */
int
hash160(unsigned char *data_in, int data_in_len, unsigned char *data_out)
{
	RIPEMD160_CTX ctx;

	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, data_in, data_in_len);
	RIPEMD160_Final(data_out, &ctx);
	return 0;
}

/* returns a string of length SHA256_DIGEST_LENGTH in data_out */
int
msg2hash256(unsigned char *msg_s, int msg_len, unsigned char *data_out)
{
        const char magic[] = "Bitcoin Signed Message:\n";
	int magic_len = strlen(magic);
        unsigned char *msg_b;
        int len;

	/* allocate var_int + msg + var_int + msg */
        msg_b = malloc(1 + magic_len + 1 + msg_len);
	if (!msg_b)
		return -1;

	/* add the magic... */
	len = 0;
        msg_b[len] = magic_len;
        len++;
        memcpy(&msg_b[len], magic, magic_len);
        len += magic_len;

	// FIXME: use variable_uint_size() for messages longer than 253 bytes
	if (msg_len > 253) {
		free(msg_b);
		return -2;
	}

	/* add the message... */
        msg_b[len] = msg_len;
	len++;
        memcpy(&msg_b[len], msg_s, msg_len);
        len += msg_len;

	dbl_hash256(msg_b, len, data_out);
        free(msg_b);
	return 0;
}

/* returns non-NULL bitcoin address upon success and sets addr_len to length. */
unsigned char *
pubkey2address(EC_KEY *pubkey, int *addr_len, int compressed)
{
	unsigned char ripemd_b[RIPEMD160_DIGEST_LENGTH];
	unsigned char checksum[SHA256_DIGEST_LENGTH];
	unsigned char bin_addr[BTC_BIN_ADDR_SIZE];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char *address, *addr, *addr2;
	int retval, pubkey_len;

	/* get public key as a binary string: 65 bytes uncompressed, 33 bytes compressed. */
	EC_KEY_set_conv_form(pubkey, compressed
		? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
        pubkey_len = i2o_ECPublicKey(pubkey, NULL);
	if (pubkey_len != (compressed ? PUBLIC_KEY_SIZE_COMPRESSED : PUBLIC_KEY_SIZE)) {
		*addr_len = -1;
		return NULL;
	}
	addr = malloc(pubkey_len);
	if (!addr) {
		*addr_len = -2;
		return NULL;
	}
	addr2 = addr;
        retval = i2o_ECPublicKey(pubkey, &addr2);
	if (retval != pubkey_len) {
		*addr_len = -3;
		free(addr);
		return NULL;
	}

	/* use the recovered pubkey to reconstruct bitcoin address. */
	hash256(addr, pubkey_len, hash);
	hash160(hash, sizeof(hash), ripemd_b);
	bin_addr[0] = 0x00;     // Network ID Byte
        memcpy(&bin_addr[1], ripemd_b, sizeof(ripemd_b));
	retval = dbl_hash256(bin_addr, 21, checksum);
	memcpy(&bin_addr[21], &checksum[0], 4);
	address = b58_encode(bin_addr, sizeof(bin_addr), addr_len);
	free(addr);
	return address;
}

/* returns 1 upon success (pubkey is recovered and signature verified)
 * otherwise < 0 for error. 
 */
int
verified_pubkey_recovery(EC_KEY *key, ECDSA_SIG *sig, 
	unsigned char *sig_bin, int sig_bin_len, unsigned char *hash, int hash_len, int *compressed)
{
	unsigned char *p64;
        int retval, rec;

	/* The first byte is the recovery parameter plus 27. 
         * If the corresponding public key is to be a compressed one,
         * 4 is added. The next 32 bytes encode r. The last 32 bytes encode s.
         */
        rec = (sig_bin[0] - 27) & ~4;
	*compressed = ((sig_bin[0] - 27) & 4) != 0;

        p64 = &sig_bin[1];
        if (rec < 0 || rec >= 3)
                return -1;
        BN_bin2bn(&p64[0],  32, sig->r);
        BN_bin2bn(&p64[32], 32, sig->s);
        // printf("(sig->r, sig->s): (%s,%s)\n", BN_bn2hex(sig->r), BN_bn2hex(sig->s));
        retval = ECDSA_SIG_recover_key_GFp(key, sig, hash, hash_len, rec, 0);
        if (retval <= 0)
                return -2;

        /* verify message, signature, and public key. */
        retval = ECDSA_do_verify(hash, hash_len, sig, key);
        if (retval <= 0)
		retval = -3;

	return retval;
}

/* verify the signature of a message. 
 * first recover the public key, then verifying the signature using message and public key, 
 * finally rebuild the bitcoin address and compare it to the address provided.
 *
 * returns 1 upon successful verification, 0 unsuccessful, < 0 for errors.
 */
int
verify_signature(pam_handle_t *pamh, char *addr_s, char *msg_s, char *sign_s)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char sign_b[SIGNATURE_SIZE];
	unsigned char *address;
	ECDSA_SIG *sig = NULL;
	EC_KEY *key = NULL;
	int retval, addr_len, msg_len, sign_len, compressed;

	addr_len = strlen(addr_s);
	msg_len  = strlen(msg_s);
	sign_len = strlen(sign_s);

	/*
	printf("verify_signature:\n  '%s' %d\n  '%s' %d\n  '%s' %d\n",
		msg_s, msg_len, sign_s, sign_len, addr_s, addr_len);
	*/
	/* decode signature string into 65 byte binary array. */
        retval = b64_decode((uint8_t *)sign_s, sign_len, sign_b);
	if (retval != SIGNATURE_SIZE) {
		pam_syslog(pamh, LOG_ERR, "signature failed to decode base64, bad len: %d", retval);
		return -1;
	}

	/* double sha256 hash of message, using electrum signature format. */
	retval = msg2hash256((unsigned char *)msg_s, msg_len, hash);
	if (retval < 0) {
		pam_syslog(pamh, LOG_ERR, "message failed to hash: too long > 253");
		return -2;
	}
	//pam_syslog(pamh, LOG_ERR, "verify_signature: '%s' %d  '%s' %d '%s' %d",
	//	msg_s, msg_len, sign_s, sign_len, addr_s, addr_len);

	/* use recovered public key from signature to verify message. */
	sig = ECDSA_SIG_new();
	key = EC_KEY_new_by_curve_name(NID_secp256k1);
	retval = verified_pubkey_recovery(key, sig, sign_b, sizeof(sign_b), hash, sizeof(hash), &compressed);
	if (retval < 0) {
		pam_syslog(pamh, LOG_ERR, "failed pubkey recovery or verification: retval=%d", retval);
		retval = -3;
		goto err;
	}

	/* create bitcoin address from public key and compare for final verifcation. */
        address = pubkey2address(key, &retval, compressed);
	if (address == NULL) {
		pam_syslog(pamh, LOG_ERR, "unable to build address from public key (retval=%d)\n", retval);
		retval = -4;
		goto err;
	}
	/*
	printf("verify_signature:\n  '%s' %d\n  '%s' %d\n  '%s' %d\n",
		msg_s, msg_len, sign_s, sign_len, addr_s, addr_len);
	*/
	//pam_syslog(pamh, LOG_ERR, "Address comparison: %s, %s, %d, %d", addr_s, address, retval, addr_len);
	if ((retval == addr_len)
		&& !memcmp(addr_s, address, addr_len))
		retval = 1;
	else
		retval = 0;
	free(address);
err:
	ECDSA_SIG_free(sig);
	EC_KEY_free(key);
	return retval;
}

/* verify_address: check address length, base58check, and checksum.
 * returns 1 upon success, 0 bad checksum, <0 error 
 */
int
verify_address(char *addr_s)
{
        unsigned char *bin_addr, checksum[SHA256_DIGEST_LENGTH];
        int addr_len, bin_addr_len;
	int retval;

	/* check length and base58 encoding. */
	if (!addr_s)
		return -1;
        addr_len = strlen(addr_s);
        if (addr_len < 27 || addr_len > 34)
                return -2;
        if (base58_check(addr_s, addr_len) < 0)
                return -3;

	/* decode from base58 to 25 byte binary array. */
        bin_addr = b58_decode((unsigned char *)addr_s, addr_len, &bin_addr_len);
        if (!bin_addr)
                return -4;
        if (bin_addr_len != BTC_BIN_ADDR_SIZE) {
		retval = -5;
		goto err;
        }

	/* check version byte. */
	if ((bin_addr[0] != 0) && (bin_addr[0] != 111)) {
		retval = -6;
		goto err;
	}

	/* compute address checksum and compare. */
        dbl_hash256(bin_addr, 21, checksum);
        if (!memcmp(&bin_addr[bin_addr_len-4], checksum, 4))
                retval = 1;
        else
		retval = 0;

err:	free(bin_addr);
        return retval;
}

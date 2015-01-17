/*
 * Copyright (c) 2014 Jay Schulist <jayschulist@gmail.com>
 * Copyright (c) 2015 Peter Surda <surda@economicsofbitcoin.com>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranties of
 * MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include <qrencode.h>
#include <microhttpd.h>
#include <time.h>
#include <json-c/json.h>

#include "baseX.h"

#include "bitid.h"
#include "json.h"
#include "qr.h"
#include "httpd.h"
#include "ansi.h"
#include "png.h"
#include "crypto.h"

enum prompts {
	BTC_ADDR,
	BTC_SIG
};

/* returns: NULL on error or on success 'msg' containing response to prompt.
 * Must free returned string.
 */
static char *
bitid_prompt(pam_handle_t * pamh, int type)
{
  	char *msg = NULL, *resp = NULL;
  	int len, retval;

  	/* build up the message we're prompting for */
  	switch (type) {
    	case BTC_ADDR:
      		msg = "bitid address: ";
      		break;

    	case BTC_SIG:
      		msg = "signature: ";
      		break;
  	}
	// FIXME: try pam_get_user() and get_authtok()
	// pam_set_item(pamh, PAM_USER_PROMPT, msg);
	retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "%s", msg);
	if ((retval != PAM_SUCCESS) || (resp == NULL)) {
		return NULL;
	}

	/* Note: must free message when done. */
  	msg = calloc(PAM_MAX_MSG_SIZE, sizeof (char));
	if (!msg) {
		free(resp);
		return NULL;
	}
  	len = strlen(resp);
	if (len >= PAM_MAX_MSG_SIZE)
		len = PAM_MAX_MSG_SIZE - 1;
  	memcpy(msg, resp, len);
	free(resp);
  	return msg;
}

/* returns: malloc string, caller must free. */
static char *
remove_whitespace(char *str)
{
	char *i, *result;
        int temp = 0;

	if (str == NULL)
		return NULL;

	result = malloc(strlen(str)+1);
	memset(result, 0, strlen(str)+1);
        for (i = str; *i; ++i) {
		if (!isspace(*i)) {
                	result[temp] = (*i);
                	++temp;
            	}
	}
        result[temp] = '\0';
        return result;
}

/* returns: malloc string, caller must free. */
static char * 
verify_access(pam_handle_t *pamh, const char *file, char *addr)
{
	char *address, *username = NULL;
	char data[1000];
	FILE *fd;
	char delims[] = ",";

	/* If no configuration then ignore, so defaults work. */
	fd = fopen(file, "r");
	if (!fd) {
		pam_syslog(pamh, LOG_ERR, "Unable to open configuration file: %s", file);
		return NULL;
  	}

	/* comments start with '#'
	 * one per line, format: bitcoin-address, username 
	 */
	while (fgets(data, 1000, fd) != NULL) {
		/* remove comments. */
		if (data[0] == '#')
			continue;
		/* remove any whitespace */
		address = remove_whitespace(strtok(data, delims));
		if (address == NULL)
			continue;
		username = remove_whitespace(strtok(NULL, delims));
                if (username == NULL) {
			free(address);
                        continue;
		}
		if (!strcmp(addr, address)) {
			free(address);
			break;
		}
		free(username);
		username = NULL;
	}
  	fclose(fd);
	return username;
}

/* generate a random nonce, default nonce_len = 16. */
static unsigned char *
generate_nonce(pam_handle_t *pamh, int nonce_len)
{
	unsigned char *key, *urand, hash[SHA256_DIGEST_LENGTH];
	unsigned char *data_out;
	int i, count, urand_size = 32;
	int randfd;
	long int r;
	time_t t;

	count = urand_size + sizeof(time_t) + sizeof(long int);
	key = malloc(count);
	if (!key)
		return NULL;

	/* read random data for use as the key. */
        randfd = open("/dev/urandom", O_RDONLY);
        if (randfd == -1) {
                pam_syslog(pamh, LOG_ERR, "Cannot open /dev/urandom: %m");
		free(key);
           	return NULL;
	}
        urand = malloc(urand_size);
        if (!urand) {
                close(randfd);
		free(key);
                return NULL;
        }
	count = 0;
        while (count < urand_size) {
                i = read(randfd, urand + count, urand_size - count);
                if ((i == 0) || (i == -1)) {
                        break;
                }
                count += i;
        }
        close(randfd); 

	/* increase entropy with random() and current time(). */
	r = random();
	t = time(NULL);

	/* build key for nonce hash */
	count = 0;
	memcpy(key + count, urand, urand_size);
	count += urand_size;
	memcpy(key + count, &r, sizeof(r));
	count += sizeof(r);
	memcpy(key + count, &t, sizeof(t));
        count += sizeof(t);
	hash256(key, count, hash);
	free(urand);
	free(key);

	data_out = malloc(nonce_len);
	if (!data_out)
		return NULL;
	memcpy(data_out, hash, nonce_len);
	return data_out;
}

static char * 
challenge(pam_handle_t *pamh, int *out_len)
{
	unsigned char *nonce;
	char *msg;
	int i, len, msg_len;

	nonce = generate_nonce(pamh, NONCE_LEN);
	if (!nonce) {
		*out_len = -1;
		return NULL;
	}

	msg_len = (NONCE_LEN + 1) * 2;
	msg = malloc(msg_len);
	if (!msg) {
		*out_len = -2;
		free(nonce);
		return NULL;
	}
	memset(msg, '\0', msg_len);

	len = 0;
	for(i = 0; i < NONCE_LEN; i++)
		len += sprintf(msg + len, "%02x", nonce[i]);
	free(nonce);

	*out_len = strlen(msg);
	return msg;
}

static int
pam_bitcoin_terminal(pam_handle_t *pamh, int flags)
{
	char *username = NULL;
  	int retval;

  	/* get bitcoin address. */
  	auth.termresp.address = bitid_prompt(pamh, BTC_ADDR);
	if (auth.termresp.address == NULL) {
    		retval = PAM_USER_UNKNOWN;
		goto end;
  	}

  	/* validate address format provided from the user. */
	retval = verify_address(auth.termresp.address);
	if (retval <= 0) {
		pam_syslog(pamh, LOG_ERR, "malformed bitcoin address used for login: error %d", retval);
		retval = PAM_USER_UNKNOWN;
		goto end;
	}

	/* lookup address to see if user can login using bitcoin. */
	username = verify_access(pamh, auth.file, auth.termresp.address);
	if (!username) {
		pam_syslog(pamh, LOG_ERR, "bitcoin address is not authorized for access: %s", auth.termresp.address);
		retval = PAM_PERM_DENIED;
		goto end;
	}

  	/* generate challenge message to sign. */
	auth.challenge = challenge(pamh, &retval);
	if (!auth.challenge || (retval < 0)) {
    		retval = PAM_SERVICE_ERR;
		goto end;
  	}
	pam_info(pamh, "challenge message: %s", auth.challenge);

  	/* get signature of message. */
  	if ((auth.termresp.signature = bitid_prompt(pamh, BTC_SIG)) == NULL) {
    		retval = PAM_AUTH_ERR;
		goto end;
	}

  	/* use signature to recover and authenticate address. */
	retval = verify_signature(pamh, auth.termresp.address, auth.challenge, auth.termresp.signature);
	if (retval <= 0) {
		pam_syslog(pamh, LOG_ERR, "user: %s failed login signature verification from: %s\n", username, auth.termresp.address);
		retval = PAM_AUTHTOK_RECOVERY_ERR;
		goto end;
	}

	/* set username details associated with this address. */
        retval = pam_set_item(pamh, PAM_USER, username);
        if (retval != PAM_SUCCESS)
                goto end;
	retval = pam_set_item(pamh, PAM_AUTHTOK, auth.termresp.signature);
	if (retval != PAM_SUCCESS)
		goto end;
	pam_syslog(pamh, LOG_INFO, "user: %s allowed access from: %s\n", username, auth.termresp.address);

end:
	return retval;
}

static int
pam_bitcoin_qr(pam_handle_t *pamh, int flags)
{
	char *username = NULL;
	struct MHD_Daemon *d = NULL;
	time_t deadline = time(NULL);
	struct response *resp;
	deadline += 60; // FIXME get from param
	int retval;

  	/* generate challenge message to sign. */
	auth.challenge = challenge(pamh, &retval);
	if (!auth.challenge || (retval < 0)) {
    		retval = PAM_SERVICE_ERR;
		goto end;
  	}

	auth.termresp.gotresponse = auth.httpresp.gotresponse = 0;

	auth.port = auth.port_lo;
	while (d == NULL && auth.port <= auth.port_hi) {
		d = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, auth.port, NULL, NULL, &bitid_callback, NULL,
			MHD_OPTION_PER_IP_CONNECTION_LIMIT, 2,
			MHD_OPTION_CONNECTION_TIMEOUT, 60,
			MHD_OPTION_NOTIFY_COMPLETED, &http_connection_closed, NULL,
			MHD_OPTION_END);
		if (d == NULL)
			auth.port ++;
	}
	if (d == NULL) {
		pam_syslog(pamh, LOG_ERR, "Cannot create http daemon. Terminal based authentication only.");
	}

	auth.challengeuri = builduri((char *) auth.hostname, auth.port, auth.challenge, BITID);
	if (auth.challengeuri == NULL) {
    		retval = PAM_SERVICE_ERR;
		goto end;
	}
	pam_info(pamh, "challenge message: %s", auth.challengeuri);

	auth.qrcode = QRcode_encodeString(auth.challengeuri, 0, QR_ECLEVEL_L, QR_MODE_8, 1);

	if (auth.qrcode == NULL) {
    		retval = PAM_SERVICE_ERR;
		goto end;
	}

	ansi_write(pamh, auth.qrcode, ANSI_TYPE);

	if (auth.httpresp.gotresponse == 0)
		auth.termresp.address = bitid_prompt(pamh, BTC_ADDR);
	if (auth.httpresp.gotresponse == 0)
		auth.termresp.signature = bitid_prompt(pamh, BTC_SIG);
	resp = &(auth.httpresp);
	if (auth.termresp.address != NULL && strcmp(auth.termresp.address, "") != 0 &&
		auth.termresp.signature != NULL && strcmp(auth.termresp.signature, "") != 0) {
		auth.termresp.gotresponse = 1;
		auth.termresp.uri = strdup (auth.challengeuri);
		//pam_syslog(pamh, LOG_ERR, "Termresp");
		resp = &(auth.termresp);
	}

	while (d != NULL && auth.termresp.gotresponse == 0 && auth.httpresp.gotresponse == 0 && time(NULL) < deadline) {
		if (auth.httpresp.gotresponse == 0)
			sleep(1); // FIXME maybe nicer?
	}
	if (resp == &(auth.httpresp)) {
		//pam_syslog(pamh, LOG_ERR, "httpresp");
	}
	else if (resp == &(auth.termresp))
		//pam_syslog(pamh, LOG_ERR, "termresp");

	if (d != NULL)
		MHD_stop_daemon(d);
	if (auth.termresp.gotresponse == 0 && auth.httpresp.gotresponse == 0) {
		pam_syslog(pamh, LOG_ERR, "Neither terminal nor http response received.");
		retval = PAM_SERVICE_ERR;
		goto end;
  	}

  	/* get bitcoin address. */
	if (resp->address == NULL) {
    		retval = PAM_USER_UNKNOWN;
		goto end;
  	}

  	/* validate address format provided from the user. */
	retval = verify_address(resp->address);
	if (retval <= 0) {
		pam_syslog(pamh, LOG_ERR, "malformed bitcoin address used for login: error %d", retval);
		retval = PAM_USER_UNKNOWN;
		goto end;
	}

	/* lookup address to see if user can login using bitcoin. */
	username = verify_access(pamh, auth.file, resp->address);
	if (!username) {
		pam_syslog(pamh, LOG_ERR, "bitcoin address is not authorized for access: %s", resp->address);
		retval = PAM_PERM_DENIED;
		goto end;
	}

	if (resp->uri == NULL || strcmp(resp->uri, auth.challengeuri) != 0) {
		pam_syslog(pamh, LOG_ERR, "URIs do not match: %s, %s", resp->uri, auth.challengeuri);
		retval = PAM_PERM_DENIED;
		goto end;
  	}

  	/* get signature of message. */
  	if (resp->signature == NULL) {
    		retval = PAM_AUTH_ERR;
		goto end;
	}


	//pam_syslog(pamh, LOG_ERR, "URIs/chal: %s, %s, %s", resp->uri, auth.challengeuri, auth.challenge);

  	/* use signature to recover and authenticate address. */
	//pam_syslog(pamh, LOG_ERR, "verify_signature: %s, %s, %s", resp->address, auth.challengeuri, resp->signature);
	retval = verify_signature(pamh, resp->address, auth.challengeuri, resp->signature);
	if (retval <= 0) {
		pam_syslog(pamh, LOG_ERR, "user: %s failed login signature verification (%s) from: %s, retval = %i", username, resp->signature, resp->address, retval);
		//pam_syslog(pamh, LOG_ERR, "Fuck it");
		retval = PAM_AUTHTOK_RECOVERY_ERR;
		goto end;
	}
	pam_syslog(pamh, LOG_ERR, "user: %s succeeded login signature verification (%s) from: %s, retval = %i", username, resp->signature, resp->address, retval);

	/* set username details associated with this address. */
        retval = pam_set_item(pamh, PAM_USER, username);
        if (retval != PAM_SUCCESS)
                goto end;
	retval = pam_set_item(pamh, PAM_AUTHTOK, resp->signature);
	if (retval != PAM_SUCCESS)
		goto end;
	pam_syslog(pamh, LOG_INFO, "user: %s allowed access from: %s\n", username, resp->address);

end:
	return retval;
}

static int
pam_bitcoin(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  	int retval;

	auth.port = auth.port_lo = auth.port_hi = 12356;

  	/* use filename for bitcoin username lookup. */

  	for (; argc-- > 0; ++argv) {
      		if (!strncmp (*argv, "file=", 5))
			auth.file = (5 + *argv);
      		else if (!strncmp (*argv, "qr=", 3))
			auth.doqr = atoi (3 + *argv);
      		else if (!strncmp (*argv, "port=", 5)) {
			retval = sscanf(5 + *argv, "%d-%d", &auth.port_lo, &auth.port_hi);
			if (retval != 2)
				auth.port = auth.port_lo = auth.port_hi = atoi (5 + *argv);
			if (auth.port_lo <= 0 || auth.port_lo > auth.port_hi)
				auth.port_lo = 1024;
			if (auth.port_hi >= 65535 || auth.port_lo > auth.port_hi)
				auth.port_hi = 65535;
      		} else if (!strncmp (*argv, "hostname=", 9))
			auth.hostname = (9 + *argv);
  	}

  	/* No file= option, must have it.  */
  	if (auth.file == NULL || auth.file[0] == '\0') {
    		pam_syslog(pamh, LOG_ERR, "bitid access configuration file path not provided");
    		retval = PAM_IGNORE;
		goto end;
  	}

	if (auth.doqr == 0)
		retval = pam_bitcoin_terminal(pamh, flags);
	else {
  		if (auth.hostname == NULL || auth.hostname[0] == '\0') {
    			pam_syslog(pamh, LOG_ERR, "no hostname provided");
    			retval = PAM_IGNORE;
			goto end;
  		}
		retval = pam_bitcoin_qr(pamh, flags);
	}
end:
	if (auth.challenge)
		free(auth.challenge);
	if (auth.challengeuri)
		free(auth.challengeuri);
	if (auth.httpresp.address)
		free(auth.httpresp.address);
	if (auth.httpresp.signature)
  		free(auth.httpresp.signature);
	if (auth.httpresp.uri)
  		free(auth.httpresp.uri);
	if (auth.termresp.address)
		free(auth.termresp.address);
	if (auth.termresp.signature)
  		free(auth.termresp.signature);
	if (auth.termresp.uri)
  		free(auth.termresp.uri);
	return retval;
}

int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
	return pam_bitcoin (pamh, flags, argc, argv);
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
	return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
	return PAM_IGNORE;
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
	return PAM_IGNORE;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
	return PAM_IGNORE;
}

/* changing authentication token, could be used to update bitcoin address
 * user is allowed to login from.
 */
int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */
struct pam_module _pam_bitcoin_modstruct = {
	"pam_bitid",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok,
};

#endif

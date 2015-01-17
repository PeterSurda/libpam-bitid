#include <string.h>
#include <json-c/json.h>
#include "bitid.h"
#include "json.h"

int decode_json_data (char *data, int len) {
	char *tmp = NULL;
	json_object *jobj = NULL;

	int retval = -1;
	
	if (len > 0) {
		tmp = calloc (len + 1, sizeof(char));
		if (tmp == NULL)
			goto end;
		strncpy(tmp, data, len);
		jobj = json_tokener_parse(tmp);
		if (jobj != NULL && !json_object_get_type (jobj) == json_type_array)
			goto end;
		json_object_object_foreach (jobj, key, val) {
			if (json_object_get_type(val) == json_type_string) {
				// uri, address, signature
				if (!strcmp(key, JSON_RESPONSE_ADDRESS))
					auth.httpresp.address = strdup(json_object_get_string(val));
				else if (!strcmp(key, JSON_RESPONSE_SIGNATURE))
					auth.httpresp.signature = strdup(json_object_get_string(val));
				else if (!strcmp(key, JSON_RESPONSE_URI))
					auth.httpresp.uri = strdup(json_object_get_string(val));
			}
		}
		if (auth.httpresp.address && auth.httpresp.signature && auth.httpresp.uri &&
			// same as requested
			!strcmp(auth.httpresp.uri, auth.challengeuri)) {
			retval = 0;
		}
	}
end:
	if (jobj)
		json_object_put(jobj);
	if (tmp)
		free (tmp);
	return retval;
}

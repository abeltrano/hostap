/*
 * Engine interface functions for OpenSSL
 * Copyright (c) 2004-2021, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <openssl/engine.h>

#include "common.h"
#include "openssl_engine.h"

/**
 * tls_engine_load_dynamic_generic - load any openssl engine
 * @pre: an array of commands and values that load an engine initialized
 *       in the engine specific function
 * @post: an array of commands and values that initialize an already loaded
 *        engine (or %NULL if not required)
 * @id: the engine id of the engine to load (only required if post is not %NULL
 *
 * This function is a generic function that loads any openssl engine.
 *
 * Returns: 0 on success, -1 on failure
 */
int tls_engine_load_dynamic_generic(const char *pre[],
					   const char *post[], const char *id)
{
	ENGINE *engine;
	const char *dynamic_id = "dynamic";

	engine = ENGINE_by_id(id);
	if (engine) {
		wpa_printf(MSG_DEBUG, "ENGINE: engine '%s' is already "
			   "available", id);
		/*
		 * If it was auto-loaded by ENGINE_by_id() we might still
		 * need to tell it which PKCS#11 module to use in legacy
		 * (non-p11-kit) environments. Do so now; even if it was
		 * properly initialised before, setting it again will be
		 * harmless.
		 */
		goto found;
	}
	ERR_clear_error();

	engine = ENGINE_by_id(dynamic_id);
	if (engine == NULL) {
		wpa_printf(MSG_INFO, "ENGINE: Can't find engine %s [%s]",
			   dynamic_id,
			   ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	/* Perform the pre commands. This will load the engine. */
	while (pre && pre[0]) {
		wpa_printf(MSG_DEBUG, "ENGINE: '%s' '%s'", pre[0], pre[1]);
		if (ENGINE_ctrl_cmd_string(engine, pre[0], pre[1], 0) == 0) {
			wpa_printf(MSG_INFO, "ENGINE: ctrl cmd_string failed: "
				   "%s %s [%s]", pre[0], pre[1],
				   ERR_error_string(ERR_get_error(), NULL));
			ENGINE_free(engine);
			return -1;
		}
		pre += 2;
	}

	/*
	 * Free the reference to the "dynamic" engine. The loaded engine can
	 * now be looked up using ENGINE_by_id().
	 */
	ENGINE_free(engine);

	engine = ENGINE_by_id(id);
	if (engine == NULL) {
		wpa_printf(MSG_INFO, "ENGINE: Can't find engine %s [%s]",
			   id, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
 found:
	while (post && post[0]) {
		wpa_printf(MSG_DEBUG, "ENGINE: '%s' '%s'", post[0], post[1]);
		if (ENGINE_ctrl_cmd_string(engine, post[0], post[1], 0) == 0) {
			wpa_printf(MSG_DEBUG, "ENGINE: ctrl cmd_string failed:"
				" %s %s [%s]", post[0], post[1],
				   ERR_error_string(ERR_get_error(), NULL));
			ENGINE_remove(engine);
			ENGINE_free(engine);
			return -1;
		}
		post += 2;
	}
	ENGINE_free(engine);

	return 0;
}

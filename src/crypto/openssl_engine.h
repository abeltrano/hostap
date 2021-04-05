/*
 * Engine interface functions for OpenSSL
 * Copyright (c) 2004-2021, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

int tls_engine_load_dynamic_generic(const char *pre[],
					   const char *post[], const char *id);

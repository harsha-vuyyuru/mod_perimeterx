ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = mod_perimeterx.la

mod_perimeterx_la_SOURCES = mod_perimeterx.c curl_pool.c px_payload.c px_json.c px_utils.c px_enforcer.c px_template.c mustach.c px_client.c
include_HEADERS = px_types.h curl_pool.h px_payload.h px_json.h px_utils.h px_enforcer.h px_template.h mustach.h px_client.h

mod_perimeterx_la_CFLAGS = @CFLAGS@ \
	@APXS_INCLUDES@ @APXS_CFLAGS@ \
	@APR_INCLUDES@ @APR_CFLAGS@ \
	@OPENSSL_INCLUDES@ \
	@CURL_CFLAGS@ \
	@JANSSON_INCLUDES@
mod_perimeterx_la_LDFLAGS = -no-undefined -module -avoid-version \
	@APXS_LIBS@ @APXS_LDFLAGS@ \
	@APR_LDFLAGS@ \
	@OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ \
	@CURL_LIBS@ @CURL_LDFLAGS@ \
	@JANSSON_LIBS@ @JANSSON_LDFLAGS@


install: $(lib_LTLIBRARIES)
	@APXS@ -i $?

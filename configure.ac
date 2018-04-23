AC_INIT([mod_perimeterx], [2.10.1], [https://github.com/PerimeterX/mod_perimeterx])
AC_PREREQ(2.63)

AC_CONFIG_AUX_DIR([buildaux])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_USE_SYSTEM_EXTENSIONS

m4_include([m4/ax_check_openssl.m4])

AC_CONFIG_SRCDIR([src/mod_perimeterx.c])
AC_CONFIG_HEADERS([src/config.h])

LT_INIT

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CANONICAL_HOST
CANONICAL_HOST=$host
AC_SUBST([CANONICAL_HOST])

AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_CONFIG_MACRO_DIR([m4])

AC_CHECK_HEADERS(sys/select.h)

AC_ARG_WITH(
    [apxs],
    [AS_HELP_STRING([--with-apxs], [full path to apxs (or apxs2) executable])],
    [AC_SUBST(APXS, $withval)],
    [AC_PATH_PROGS(APXS, [apxs apxs2])])
if test ! -x "$APXS"; then
    AC_MSG_ERROR(["Can't find APXS installation. Please specify --with-apxs=PATH, where PATH is the full path to apxs (or apx2) executable."])
fi
APXS_CFLAGS=`$APXS -q CFLAGS`
APXS_INCLUDES=-I`$APXS -q INCLUDEDIR`
APXS_LDFLAGS=`$APXS -q LDFLAGS_SHLIB`
APXS_LIBS=`$APXS -q LIBS_SHLIB`
APXS_LIBEXECDIR=`$APXS -q LIBEXECDIR`
AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_INCLUDES)
AC_SUBST(APXS_LIBS)
AC_SUBST(APXS_LDFLAGS)
AC_SUBST(APXS_LIBEXECDIR)

AC_ARG_WITH(
    [apr],
    [AS_HELP_STRING([--with-apr], [full path to Apache APR config utility (apr-1-config)])],
    [AC_SUBST(APR, $withval)],
    [AC_PATH_PROGS(APR, [apr-1-config])])
if test ! -x "$APR"; then
    AC_MSG_ERROR(["Can't find Apache APR installation. Please specify --with-apr=PATH, where PATH is the full path to Apache APR config utility (apr-1-config)."])
fi
APR_CFLAGS=`$APR --cflags`
APR_INCLUDES=`$APR --includes`
APR_LDFLAGS=`$APR --link-libtool --libs`
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_INCLUDES)
AC_SUBST(APR_LDFLAGS)

AX_CHECK_OPENSSL([], [AC_MSG_ERROR([Can't find OpenSSL installation. Please specify –with-openssl=PATH, where PATH is the full path to OpenSSL installation directory.])])

AC_ARG_WITH(
    [curl],
    [AS_HELP_STRING([--with-curl], [full path to cURL installation directory.])],
    [AC_SUBST(CURL_CONFIG, $withval)],
    [AC_PATH_PROGS(CURL_CONFIG, [curl-config])])
if test ! -x "$CURL_CONFIG"; then
    AC_MSG_ERROR(["Can't find cURL installation. Please specify --with-curl=PATH, where PATH is the full path to cURL installation directory."])
fi
CURL_CFLAGS="`${CURL_CONFIG} --cflags`"
CURL_LIBS="`${CURL_CONFIG} --libs`"
CURL_LDADD="${CURL_LIBS}"
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LDFLAGS)
AC_SUBST(CURL_LIBS)

AX_CHECK_JANSSON([], [AC_MSG_ERROR([Can't find libjansson installation. Please specify –with-jansson=PATH, where PATH is the full path to libjansson installation directory.])])

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug], [enable debug build]),
    [], [enable_debug=no])
if test "x$enable_debug" = "xyes" ; then
    CFLAGS="$CFLAGS -DDEBUG=1"
    AC_DEFINE([DEBUG], [1], [enable debug build])
fi

AC_ARG_ENABLE(module,
    AS_HELP_STRING([--enable-module], [enable module in Apache configuration]),
    [], [enable_module=no])
AM_CONDITIONAL([ENMOD], [test x$enable_module = xyes])

AX_CODE_COVERAGE

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    build/rpm/mod_perimeterx.spec
    build/build_centos.sh
    build/build_ubuntu.sh
    build/build_debian.sh
    contrib/version.sh
])

AC_OUTPUT

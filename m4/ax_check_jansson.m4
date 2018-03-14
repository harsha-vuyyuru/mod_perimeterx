# SYNOPSIS
#
#   AX_CHECK_JANSSON([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for jansson in a number of default spots, or in a user-selected
#   spot (via --with-jansson).  Sets
#
#     JANSSON_INCLUDES to the include directives required
#     JANSSON_LIBS to the -l directives required
#     JANSSON_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets JANSSON_INCLUDES such that source files should include
#   jansson.h like so:
#
#     #include <jansson.h>
#
# LICENSE
# Based on
#     https://www.gnu.org/software/autoconf-archive/ax_check_jansson.html
#
#   Copyright (c) 2009,2010 Zmanda Inc. <http://www.zmanda.com/>
#   Copyright (c) 2009,2010 Dustin J. Mitchell <dustin@zmanda.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AU_ALIAS([CHECK_JANSSON], [AX_CHECK_JANSSON])
AC_DEFUN([AX_CHECK_JANSSON], [
    found=false
    AC_ARG_WITH([jansson],
        [AS_HELP_STRING([--with-jansson=DIR],
            [root of the jansson directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-jansson value])
              ;;
            *) janssondirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is installed and jansson has installed a .pc file,
            # then use that information and don't search janssondirs
            AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                JANSSON_LDFLAGS=`$PKG_CONFIG jansson --libs-only-L 2>/dev/null`
                if test $? = 0; then
                    JANSSON_LIBS=`$PKG_CONFIG jansson --libs-only-l 2>/dev/null`
                    JANSSON_INCLUDES=`$PKG_CONFIG jansson --cflags-only-I 2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default janssondirs
            if ! $found; then
                janssondirs="/usr/local/jansson /usr/lib/jansson /usr/jansson /usr/pkg /usr/local /usr"
            fi
        ]
        )


    if ! $found; then
        JANSSON_INCLUDES=
        for janssondir in $janssondirs; do
            AC_MSG_CHECKING([for jansson.h in $janssondir])
            if test -f "$janssondir/include/jansson/jansson.h"; then
                JANSSON_INCLUDES="-I$janssondir/include/jansson"
                JANSSON_LDFLAGS="-L$janssondir/lib"
                JANSSON_LIBS="-ljansson"
                found=true
                AC_MSG_RESULT([yes])
                break
            else
                AC_MSG_RESULT([no])
            fi
        done

        # if the file wasn't found, well, go ahead and try the link anyway -- maybe
        # it will just work!
    fi

    # try the preprocessor and linker with our new flags,
    # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

    AC_MSG_CHECKING([whether compiling and linking against jansson works])
    echo "Trying link with JANSSON_LDFLAGS=$JANSSON_LDFLAGS;" \
        "JANSSON_LIBS=$JANSSON_LIBS; JANSSON_INCLUDES=$JANSSON_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $JANSSON_LDFLAGS"
    LIBS="$JANSSON_LIBS $LIBS"
    CPPFLAGS="$JANSSON_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <jansson.h>], [(json_loads)])],
        [
            AC_MSG_RESULT([yes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
        ])
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([JANSSON_INCLUDES])
    AC_SUBST([JANSSON_LIBS])
    AC_SUBST([JANSSON_LDFLAGS])
])

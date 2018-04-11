#!/bin/sh
cd `dirname "$0"`

ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOHEADER=${AUTOHEADER:-autoheader}
LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}

set -ex
"$LIBTOOLIZE" --copy --force
"$ACLOCAL" -I m4
"$AUTOCONF"
"$AUTOHEADER"
"$AUTOMAKE" --force-missing --add-missing --copy

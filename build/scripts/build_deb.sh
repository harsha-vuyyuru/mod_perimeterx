#!/bin/bash

if [ -z "$VERSION" ]; then
    echo "$VERSION environment variable is not set!"
    exit 1
fi

if [ -z "$DISTR" ]; then
    echo "$DISTR environment variable is not set!"
    exit 1
fi

mkdir /build
cd /build
tar -xzf /src/mod_perimeterx-$VERSION.tar.gz
cd mod_perimeterx-$VERSION/
debuild --no-lintian -uc -us -b -tc
cd ../
OUT_DIR=/packages/$DISTR/
if [ ! -d "$OUT_DIR" ]; then
    mkdir $OUT_DIR || true
fi
cp libapache2-mod-perimeterx_$VERSION_*.deb $OUT_DIR

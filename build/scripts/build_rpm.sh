#!/bin/bash

if [ -z "$VERSION" ]; then
    echo "$VERSION environment variable is not set!"
    exit 1
fi

if [ -z "$DISTR" ]; then
    echo "$DISTR environment variable is not set!"
    exit 1
fi

cd /root
mkdir /root/rpmbuild
cd /root/rpmbuild
mkdir SOURCES SPECS
cp /src/mod_perimeterx-$VERSION.tar.gz /root/rpmbuild/SOURCES/
cp /mod_perimeterx.spec /root/rpmbuild/SPECS/
cd /root/rpmbuild/SPECS/
rpmbuild -bb mod_perimeterx.spec
OUT_DIR=/packages/$DISTR/
if [ ! -d "$OUT_DIR" ]; then
    mkdir $OUT_DIR || true
fi
cp /root/rpmbuild/RPMS/x86_64/mod_perimeterx-$VER*.rpm $OUT_DIR

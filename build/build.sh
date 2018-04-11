#!/bin/bash

if [ ! -f ./build_centos.sh -o ! -f ./build_ubuntu.sh  ]; then
    echo "Please run ./configure script from the project's root directory"
    exit 1
fi
/bin/bash ./build_debian.sh
/bin/bash ./build_centos.sh
/bin/bash ./build_ubuntu.sh

echo
echo "Packages are in $(pwd)/packages/ folder"
echo

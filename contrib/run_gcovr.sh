#!/bin/sh
if ! [ -x "$(command -v gcovr)" ]; then
    echo "gcovr is not installed."
    exit 1
fi

python2 /usr/bin/gcovr -r . --html --html-details -o code-coverage.html

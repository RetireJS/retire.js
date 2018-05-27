#!/bin/env bash

PYTHON_VERSION=$(python -c 'import sys; print("%i" % (sys.hexversion<0x03000000))')

if [ -z "$1" ]; then
    PORT=8000
else
    PORT=$1
fi

cd repository

if [ ${PYTHON_VERSION} -eq 0 ]; then
    python -m http.server $PORT
else
    python -m SimpleHTTPServer $PORT
fi

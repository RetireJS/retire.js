#!/bin/sh
set -e

cd node
npm install
cd ..
cd chrome/build
npm install
npm run build
cd ../..

echo "Done!"

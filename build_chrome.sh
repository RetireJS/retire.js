#!/bin/sh
set -e

cd node
npm install
npm run build
cd ..
cd chrome/build
npm install
npm run build
cd ../..

echo "Done!"

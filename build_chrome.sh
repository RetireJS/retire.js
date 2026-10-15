#!/bin/sh
set -e
cd "$(dirname "$0")"

cd node
npm install
npm run build
cd ..

cd chrome/build
npm install
npm run build
cd ../..

echo "Built chrome/extension, chrome/extension-no-func, and dist/firefox."

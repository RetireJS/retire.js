#!/bin/sh
set -e
cd "$(dirname "$0")"

cd node
npm ci --no-audit --no-fund
npm run build
cd ..

cd chrome/build
npm ci --no-audit --no-fund
npm run build
cd ../..

echo "Built Chrome, Chrome no-func, and Firefox packages in dist."

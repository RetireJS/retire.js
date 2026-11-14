#!/bin/sh
set -e
cd "$(dirname "$0")"
case "${1:-build}" in
  build) ./build_chrome.sh ;;
  test) (cd node && npm run build && npm test); (cd chrome/build && npm test) ;;
  *) echo "Usage: ./fx.sh [build|test]"; exit 1 ;;
esac
echo "Load dist/firefox/manifest.json from about:debugging in Firefox."

#!/bin/sh

FILEPATH=$(dirname $0)/chrome/js/retire.js

echo "Building $FILEPATH ..."

echo "var retire = (function(){" > $FILEPATH
cat node/lib/retire.js >> $FILEPATH
echo "return exports; })();" >> $FILEPATH

echo "Done!"

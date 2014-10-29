#!/bin/sh

FILEPATH=$(dirname $0)/chrome/js/retire.js

echo "Building $FILEPATH ..."
echo "\xef\xbb\xbfvar retire = (function(){" > $FILEPATH
cat node/lib/retire.js >> $FILEPATH
echo "return exports; })();" >> $FILEPATH


echo "Done!"

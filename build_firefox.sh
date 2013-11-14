#!/bin/sh

# fixme: better name for filepath

FILEPATH=$(dirname $0)/firefox/lib/retire.js

if (grep -Fxq "var exports = exports || {};" node/lib/retire.js); then
  echo "Building $FILEPATH ..."
  cat node/lib/retire.js >> $FILEPATH
  sed -i.bak s/"var exports = exports || {};"/"if (typeof exports != \"object\") exports = {};"/g $FILEPATH
  rm $FILEPATH."bak"
  /usr/local/addon-sdk-1.14/bin/cfx xpi --pkgdir $(dirname $0)/firefox
  echo "Done!"
else
  echo "Build failed. Reason: Could not replace 'exports' declaration in node/lib/retire.js"
fi



#!/bin/sh

# ------------------------------------------------------------------------------
# Defaults:
# ------------------------------------------------------------------------------

ADD_ON_DIR=./
NODE_RETIRE_JS_FILE=../node/lib/retire.js
FX_RETIRE_JS_FILE=$ADD_ON_DIR/lib/retire.js
FX_PROFILE_DIR=""

target=$1

# ------------------------------------------------------------------------------
# check if the cfx tool exist
# ------------------------------------------------------------------------------

if ! type cfx > /dev/null; then
  echo "Aborting cfx command not found"
  exit 1
fi


# ------------------------------------------------------------------------------
# puts out the help text
# ------------------------------------------------------------------------------

function howToUse() {
  echo "Usage: $0 target [target-specific options]"
  echo
  echo "Targets:"
  echo "  test    - run the tests"
  echo "  run     - run the add-on in a browser"
  echo "  build   - exports the xpi"
  echo
  echo "Options:"
  echo "  -p PROFILEDIR"
  echo "     Use an existing profile located in PROFILEDIR. If the PROFILEDIR does not exist it will be automatically created."
  echo
  exit 1
}

# ------------------------------------------------------------------------------
# create the firfox/lib/retire.js file based on the node/lib/retire.js
# ------------------------------------------------------------------------------

createRetireJs() {
  if (grep -Fxq "var exports = exports || {};" $NODE_RETIRE_JS_FILE); then
    cat $NODE_RETIRE_JS_FILE > $FX_RETIRE_JS_FILE
    sed -i.bak s/"var exports = exports || {};"/"if (typeof exports != \"object\") exports = {};"/g $FX_RETIRE_JS_FILE
    rm $FX_RETIRE_JS_FILE."bak"
  else
    echo "Exit. Could not create $FX_RETIRE_JS_FILE"
    exit 1
  fi
}

# ------------------------------------------------------------------------------
# parsing command line parameters
# ------------------------------------------------------------------------------

while [ "$2" != "" ]; 
do
  case $2 in
    -p | --profiledir ) 
      shift
      FX_PROFILE_DIR=$2
      ;;
  esac
  shift
done

# ------------------------------------------------------------------------------
# runs the tests
# ------------------------------------------------------------------------------

runTests() {
  cfx test
}

# ------------------------------------------------------------------------------
# runs the add-on in the browser
# ------------------------------------------------------------------------------

runBrowser() {
  if [ -z $FX_PROFILE_DIR ] 
  then
    cfx run
  else
    cfx run -p $FX_PROFILE_DIR
  fi
}

# ------------------------------------------------------------------------------
# creates an xpi
# ------------------------------------------------------------------------------

exportXpi() {
  cfx xpi
  echo "Add-on exported to: retire.xpi"
  echo 
}

# ------------------------------------------------------------------------------
# prepearing
# ------------------------------------------------------------------------------

createRetireJs

cd $ADD_ON_DIR
case "$target" in
  "test")
    runTests
    ;;
  "run")
    runBrowser
    ;;
  "build")
    exportXpi
    ;;
  "-help")
    howToUse
    ;;
  *)
    echo
    echo "$0: Target not supported (yet): $target"
    echo
    howToUse
    exit 1
    ;;
esac  
  

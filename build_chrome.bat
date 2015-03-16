@echo off

echo "Building $FILEPATH ..."

copy bom chrome\js\retire.js
echo var retire = (function(){ >> chrome\js\retire.js
type node\lib\retire.js >> chrome\js\retire.js
echo return exports; })(); >> chrome\js\retire.js

echo "Done!"

#!/bin/bash
set -e

VERSION=$(cat package.json  | jq -r .version)
COMMIT_ID=$(git rev-parse HEAD)
echo "Point $VERSION to $COMMIT_ID and publish (Y/N)?"

if [ $(git tag -l $VERSION) ]; then
    echo "ERROR: A tag already exists for $VERSION"
    echo "Aborting...";
    exit 1;
fi


read -r -p "Are you sure? [y/N] " response
if [[ "$response" =~ ^([yY])$ ]]
then
    echo "Publishing to npm..."
    npm publish
    echo "Tagging..."
    git tag $VERSION $COMMIT_ID
    git push --tags
    echo "Done!"
else
    echo "Aborting"
fi

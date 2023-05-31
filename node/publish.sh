#!/bin/bash
set -e

npm install

if [[ `git status --porcelain` ]]; then
  echo "ERROR: Changes found in git"
  exit 1
fi

npm run check
npm run build

npm test


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
    echo "Tagging..."
    git tag $VERSION $COMMIT_ID -m "Release of version $VERSION"
    git push --tags
    echo "Done!"
    gh release create "$VERSION" -F CHANGELOG.md
else
    echo "Aborting"
fi

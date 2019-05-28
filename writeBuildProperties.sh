#!/bin/bash

VERS=`grep version package.json | head -1 | awk -F: '{ print $2 }' | sed 's/[",]//g' | tr -d '[[:space:]]'`
MAJOR=$(echo $VERS | cut -d'.' -f1)
MINOR=$(echo $VERS | cut -d'.' -f2)
PATCH=$(echo $VERS | cut -d'.' -f3)

if [ -z $LEVEL ]; then
  LEVEL=1
fi
if [ -z $BUILD_NUMBER ]; then
  BUILD_NUMBER=9999
fi

cat > src/build-properties.js << EOF
let BuildProperties = {
  major: $MAJOR,
  minor: $MINOR,
  patch: $PATCH,
  build: $BUILD_NUMBER,
  level: $LEVEL
};

/*
build:
  1: development
  2: beta
  3: release candidate
  4: hotfix
  5: final release
*/

module.exports = BuildProperties;
EOF

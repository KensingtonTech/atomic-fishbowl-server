set -x

MAJOR=1
MINOR=0
PATCH=0

if [[ $branch =~ "develop" ]]; then
  LEVEL=1
elif [[ $branch =~ "python3" ]]; then
  LEVEL=3
elif [[ $branch =~ "release" ]]; then
  LEVEL=3
elif [[ $branch =~ "rsac-2018" ]]; then
  LEVEL=3
elif [[ $branch =~ "hotfix" ]]; then
  LEVEL=4
elif [[ $branch =~ "master" ]]; then
  LEVEL=5
else
  LEVEL=1
fi

PKGNAME="afb-server"
ARTIFACTNAME="afb-docker-server"
VER="$MAJOR.$MINOR.$PATCH.$BUILD_NUMBER-$LEVEL"
REPONAME="kentechrepo:5000"
BASEDIR=$(pwd)
DISTDIR="$BASEDIR/dist"
SRCDIR="$BASEDIR/src"
WORKERDIR="worker"
FEEDERDIR="feeder"

cat > $SRCDIR/build-properties.js << EOF
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

# Install js modules
npm install
AFBDEBUG=1

echo "\$forceDebugBuild = $forceDebugBuild"

if [[ "$LEVEL" -ne 1 && "$forceDebugBuild" == "false" ]]; then
  # non-dev build
  
  DOCKERFILE='Dockerfile'
  AFBDEBUG=0
  
  if [ "$serverType" == "nw" ]; then
    npm run buildnw
  elif [ "$serverType" == "sa" ]; then
    npm run buildsa
  fi
  cd $BASEDIR

else
  # dev build

  DOCKERFILE='Dockerfile-dev'
  if [ "$serverType" == "sa" ]; then
    cp -f $SRCDIR/servicetype-sa.js $SRCDIR/servicetype.js
  elif [ "$serverType" == "nw" ]; then
    cp -f $SRCDIR/servicetype-nw.js $SRCDIR/servicetype.js
  fi
  # if a dev build, create server.js symlink
  # ln -s $SRCDIR/index.js server.js
fi

#rm -f *.mustache
#rm -f package.json package-lock.json


# now build the docker container
docker pull centos:centos7
docker build -f $DOCKERFILE --build-arg AFBDEBUG=$AFBDEBUG --build-arg CACHE_DATE=$(date +%Y-%m-%d:%H:%M:%S) -t ${PKGNAME}:${VER} -t ${PKGNAME}:latest -t ${REPONAME}/${PKGNAME}:latest -t ${REPONAME}/${PKGNAME}:${VER} .

# push our two tags to our private registry
docker push ${REPONAME}/${PKGNAME}:${VER}
docker push ${REPONAME}/${PKGNAME}:latest

# create artifact
docker save ${PKGNAME}:${VER} ${PKGNAME}:latest | gzip > ${ARTIFACTNAME}_${VER}.tgz
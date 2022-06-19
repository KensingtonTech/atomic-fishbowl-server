set -xe

VERS=`grep version package.json | head -1 | awk -F: '{ print $2 }' | sed 's/[",]//g' | tr -d '[[:space:]]'`
MAJOR=$(echo $VERS | cut -d'.' -f1)
MINOR=$(echo $VERS | cut -d'.' -f2)
PATCH=$(echo $VERS | cut -d'.' -f3)

if [[ $branch =~ "develop" ]]; then
  LEVEL=1
elif [[ $branch =~ "python3" ]]; then
  LEVEL=3
elif [[ $branch =~ "release" ]]; then
  LEVEL=3
elif [[ $branch =~ "hotfix" ]]; then
  LEVEL=4
elif [[ $branch =~ "master" ]]; then
  LEVEL=5
else
  LEVEL=1
fi

PKGNAME="atomic-fishbowl-server"
ARTIFACTNAME="afb-docker-server"
if [[ "$LEVEL" -eq 4 || "$LEVEL" -eq 5 ]]; then
  VER="$MAJOR.$MINOR.$PATCH.$BUILD_NUMBER"
else
  VER="$MAJOR.$MINOR.$PATCH.$BUILD_NUMBER-$LEVEL"  
fi
BASEDIR=$(pwd)
SRCDIR="$BASEDIR/src"
NODE_VERSION="16.15.0"
IMAGE_PREFIX="kensingtontech"

cat > $SRCDIR/build-properties.ts << EOF
export const BuildProperties = {
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
EOF

echo "\$forceDebugBuild = $forceDebugBuild"

docker pull node:${NODE_VERSION}

if [[ "$LEVEL" -ne 1 && "$forceDebugBuild" == "false" ]]; then
 # Prod build
  docker build --build-arg NODE_VERSION="${NODE_VERSION}" --no-cache -f Dockerfile-prod -t ${PKGNAME}:${VER} . \
  && docker rmi $(docker images --filter=label=stage=builder --quiet)
else
  # Dev build
  docker build --build-arg NODE_VERSION="${NODE_VERSION}" --no-cache -f Dockerfile-prod -t ${PKGNAME}:${VER} --build-arg LOG_LEVEL=debug . \
  && docker rmi $(docker images --filter=label=stage=builder --quiet)
fi

# push our tags to docker hub
if [ $DEPLOY = "true" ]; then
  docker tag ${PKGNAME}:${VER} ${IMAGE_PREFIX}/${PKGNAME}:${VER}
  docker push ${IMAGE_PREFIX}/${PKGNAME}:${VER}
  if [ $LEVEL -eq 5 ]; then
    docker image tag ${PKGNAME}:${VER} ${PKGNAME}:latest
    docker image tag ${PKGNAME}:${VER} ${IMAGE_PREFIX}/${PKGNAME}:latest
    docker push ${PKGNAME}:latest
  fi
fi

# create artifact
# docker save ${PKGNAME}:${VER} ${PKGNAME}:latest | gzip > ${ARTIFACTNAME}_${VER}.tgz
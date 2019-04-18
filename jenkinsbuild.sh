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

cat > build-properties.js << EOF
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
if [ "$serverType" == "sa" ]; then
  cp -f servicetype-sa.js servicetype.js
  DEFAULTSERVICEPREF="defaultsapreferences.js"
else
  cp -f servicetype-nw.js servicetype.js
  DEFAULTSERVICEPREF="defaultnwpreferences.js"
fi

if [ "$LEVEL" -ne 1 ]; then
  AFBDEBUG=0
  rm -rf $DISTDIR
  mkdir -p $DISTDIR/$WORKERDIR $DISTDIR/$FEEDERDIR
  # uglify the JS if not a dev build
  cd $SRCDIR && uglifyjs build-properties.js logging.js database.js token-manager.js configuration.js servicetype.js defaultpreferences.js kentech-public-key.js $DEFAULTSERVICEPREF usecases.js feed-scheduler.js fixed-collections.js rolling-collections.js user.js index.js --toplevel --compress --mangle --ecma 6 -o $DISTDIR/server.js --source-map url="server.js.map"
  
  PYTHONINCLUDE="-I/usr/include/python3.6m"
  LDFLAGS=""
  if $(uname -a | grep -q ^Darwin); then 
    PYTHONINCLUDE="-I/opt/local/Library/Frameworks/Python.framework/Versions/3.6/include/python3.6m"
    LDFLAGS="-L/opt/local/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/config-3.6m-darwin -lpython3.6m"
  fi

  # Compile python if not a dev build
  WORKERSRC='worker worker_fetcher worker_communicator worker_contentobj worker_contentprocessor worker_feedmanager'
  FEEDERSRC='feeder_srv feeder_hasher feeder_communicator'
  cd $SRCDIR/$WORKERDIR
  for f in $WORKERSRC; do
    if $(cython -3 $f.py -o $f.c); then
      gcc -shared -pthread -fPIC -fwrapv -O2 -Wall -fno-strict-aliasing $PYTHONINCLUDE $LDFLAGS -o $f.so $f.c && mv $f.so $DISTDIR/$WORKERDIR && rm -f $f.c
    fi
  done
  cp $SRCDIR/$WORKERDIR/worker_stub.py $DISTDIR/$WORKERDIR

  cd $SRCDIR/$FEEDERDIR
  for f in $FEEDERSRC; do
    if $(cython -3 $f.py -o $f.c); then
      gcc -shared -pthread -fPIC -fwrapv -O2 -Wall -fno-strict-aliasing $PYTHONINCLUDE $LDFLAGS -o $f.so $f.c && mv $f.so $DISTDIR/$FEEDERDIR && rm -f $f.c
    fi
  done
  cp $SRCDIR/$FEEDERDIR/feeder_stub.py $DISTDIR/$FEEDERDIR
  cd $BASEDIR
else
  # if a dev build, create server.js symlink
  ln -s index.js server.js
fi

#rm -f *.mustache
#rm -f package.json package-lock.json


#now build the docker container
#docker build -t ${PKGNAME}:${VER} -t ${PKGNAME}:latest -t ${REPONAME}/${PKGNAME}:latest -t ${REPONAME}/${PKGNAME}:${VER} .
docker build --build-arg AFBDEBUG=$AFBDEBUG --build-arg CACHE_DATE=$(date +%Y-%m-%d:%H:%M:%S) -t ${PKGNAME}:${VER} -t ${PKGNAME}:latest -t ${REPONAME}/${PKGNAME}:latest -t ${REPONAME}/${PKGNAME}:${VER} .

#push our two tags to our private registry
docker push ${REPONAME}/${PKGNAME}:${VER}
docker push ${REPONAME}/${PKGNAME}:latest

#create artifact
docker save ${PKGNAME}:${VER} ${PKGNAME}:latest | gzip > ${ARTIFACTNAME}_${VER}.tgz
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
  # uglify the JS if not a dev build
  uglifyjs build-properties.js servicetype.js defaultpreferences.js kentech-public-key.js $DEFAULTSERVICEPREF usecases.js feed-scheduler.js fixed-collections.js rolling-collections.js user.js index.js --toplevel --compress --mangle --ecma 6 -o server.out --source-map url="server.js.map"
  rm -f *.js
  mv server.out server.js
  
  # Compile python if not a dev build
  PYCOMPILE='worker worker_fetcher worker_contentobj worker_communicator worker_contentprocessor worker_feedmanager feeder_srv feeder_hasher feeder_communicator'
  for f in $PYCOMPILE; do
  	#if $(cython $f.py -o $f.c); then
    if $(cython -3 $f.py -o $f.c); then
      #gcc -shared -pthread -fPIC -fwrapv -O2 -Wall -fno-strict-aliasing -I/usr/include/python2.7 -o $f.so $f.c
      #gcc -shared -pthread -fPIC -fwrapv -O2 -Wall -fno-strict-aliasing -I/usr/include/python3.4m -o $f.so $f.c
      gcc -shared -pthread -fPIC -fwrapv -O2 -Wall -fno-strict-aliasing -I/usr/include/python3.6m -o $f.so $f.c
    fi
  done
  rm -f *.c
  rm -f worker.py worker_fetcher.py worker_communicator.py worker_contentobj.py worker_contentprocessor.py worker_feedmanager.py feeder_srv.py feeder_hasher.py feeder_communicator.py
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
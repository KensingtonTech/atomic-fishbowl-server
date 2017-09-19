#!/bin/bash

ETCDIR=/etc/kentech/221b
CFGFILE=221b-server.conf

if [ ! -d ${HOST}${ETCDIR} ]; then
  echo Creating $ETCDIR
  mkdir -p ${HOST}${ETCDIR}
fi

# Create a .default version of our cfg file for reference
cp -f /opt/kentech/221b-server/bin/$CFGFILE ${HOST}${ETCDIR}/${CFGFILE}.default
if [ ! -f ${HOST}${ETCDIR}/$CFGFILE ]; then
  # If our cfg file doesn't exist on the host, then create it
  echo "Creating 221B server configuration file"
  mv -f /opt/kentech/221b-server/bin/$CFGFILE ${HOST}${ETCDIR}/${CFGFILE}
fi

# Stop existing container, if already running
WASSTARTED=0
chroot $HOST /usr/bin/docker ps -f name=$NAME | grep -q ${NAME}$
if [ $? -eq 0 ]; then
  WASSTARTED=1
  echo Stopping container $NAME
  chroot $HOST /usr/bin/docker stop $NAME
fi

# Remove existing container, if present
chroot $HOST /usr/bin/docker ps -a -f name=$NAME | grep -q ${NAME}$
if [ $? -eq 0 ]; then
  echo Removing existing $NAME container
  chroot $HOST /usr/bin/docker rm $NAME
fi

# Create network '221b-network' if not already there
chroot $HOST /usr/bin/docker network ls  | awk '{print $2}' | grep -q ^221b-network$
if [ $? -ne 0 ]; then
  echo Creating bridge network 221b-network
  chroot $HOST /usr/bin/docker network create 221b-network >/dev/null
fi

# Create container
echo Creating container $NAME from image $IMAGE
chroot $HOST /usr/bin/docker create --name $NAME --network 221b-network -v /etc/kentech:/etc/kentech:ro -v /var/kentech:/var/kentech:rw -e SYSTEMD=1 $IMAGE

# Copy systemd unit file to host OS
echo Installing systemd unit file
echo "To control, use:  systemctl [ start | stop | status | enable | disable ] $NAME"
cp -f /usr/lib/systemd/system/${NAME}.service ${HOST}/etc/systemd/system

# Load our systemd unit file
chroot $HOST /usr/bin/systemctl daemon-reload

if [[ $WASSTARTED -eq 1 ]]; then
  echo Starting container $NAME
  chroot $HOST /usr/bin/systemctl start $NAME
fi

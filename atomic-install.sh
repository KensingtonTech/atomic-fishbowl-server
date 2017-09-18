#!/bin/bash

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

# Create container
echo Creating container $NAME from image $IMAGE
chroot $HOST /usr/bin/docker create --name $NAME --net=host -p 127.0.0.1:3002:3002 -v /etc/kentech:/etc/kentech:ro -v /var/kentech:/var/kentech:rw -e SYSTEMD=1 $IMAGE

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

#!/bin/bash

# Stop existing container, if already running
WASSTARTED=0
chroot $HOST /usr/bin/docker ps -f name=$NAME | grep -q ${NAME}$
if [ $? -eq 0 ]; then
  WASSTARTED=1
  echo Stopping container $NAME
  chroot $HOST /usr/bin/docker stop $NAME >/dev/null
fi

# Remove existing container, if present
# We don't need the below code anymore, as atomic now deletes the container on its own for some daft reason
#chroot $HOST /usr/bin/docker ps -a -f name=$NAME | grep -q ${NAME}$
#if [ $? -eq 0 ]; then
#  echo Removing existing $NAME container
#  chroot $HOST /usr/bin/docker rm $NAME >/dev/null
#else
#  echo Container $NAME was not found
#fi

# Remove systemd unit file
if [ -f "$HOST/etc/systemd/system/$NAME.service" ]; then
  echo Removing systemd unit file
  rm -f $HOST/etc/systemd/system/$NAME.service
  
  # Reload systemd unit files
  echo Reloading systemd config
  chroot $HOST /usr/bin/systemctl daemon-reload
fi
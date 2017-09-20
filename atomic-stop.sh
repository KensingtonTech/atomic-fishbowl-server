#!/bin/bash

echo Stopping container $NAME

# Stop existing container, if already running
chroot $HOST /usr/bin/docker ps -f name=$NAME | grep -q ${NAME}$
if [ $? -eq 0 ]; then
  chroot $HOST /usr/bin/docker stop $NAME >/dev/null
fi

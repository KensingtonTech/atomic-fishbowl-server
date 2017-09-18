#!/bin/bash

# Stop existing 221b-server container, if already running
WASSTARTED=0
chroot $HOST /usr/bin/docker ps -f name=$NAME | grep -q ${NAME}$
if [ $? -eq 0 ]; then
  WASSTARTED=1
  echo Container $NAME is already running
  exit
fi

# is our container already installed?
chroot $HOST /usr/bin/docker ps -a -f name=$NAME | grep -q ${NAME}$
if [ $? -eq 0 ]; then

  # Our container is installed, so run the installed version (don't perform an upgrade)

  if [ -f $HOST/etc/systemd/system/221b-server.service ]; then
    # our systemd unit is installed so start with systemd
    chroot $HOST /usr/bin/systemctl start $NAME
  
  else
    # no systemd unit file is installed, so start with docker
    chroot $HOST /usr/bin/docker start $NAME
  fi

else
  # the container is not installed - run the installer
  chroot $HOST /usr/bin/atomic install $NAME
  chroot $HOST /usr/bin/systemctl start $NAME
fi

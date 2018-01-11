#!/bin/bash

ETCDIR=/etc/kentech/afb
CERTDIR=$ETCDIR/certificates

# Check if existing container is already running
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


  if [ ! -d ${HOST}${CERTDIR} ]; then
    echo Creating $CERTDIR
    mkdir -p ${HOST}${CERTDIR}
  fi

  # We need both internal.key and internal.cer to exist
  if [[ -f ${HOST}${CERTDIR}/internal.key && ! -f ${HOST}${CERTDIR}/internal.cer ]]; then
    echo "Missing ${CERTDIR}/internal.cer.  Renaming $CERTDIR/internal.key to internal.key.old"
    mv -f ${HOST}${CERTDIR}/internal.key ${HOST}${CERTDIR}/internal.key.old
  fi

  if [[ ! -f ${HOST}${CERTDIR}/internal.key && -f ${HOST}${CERTDIR}/internal.cer ]]; then
    echo "Missing $CERTDIR/internal.key.  Renaming $CERTDIR/internal.cer to internal.cer.old"
    mv -f ${HOST}${CERTDIR}/internal.cer ${HOST}${CERTDIR}/internal.cer.old
  fi

  # Generate the internal keypair
  if [[ ! -f ${HOST}${CERTDIR}/internal.key || ! -f ${HOST}${CERTDIR}/internal.cer ]]; then
    echo "Generating new internal SSL keypair"
    chroot $HOST /usr/bin/openssl genrsa -out $CERTDIR/internal.key 2048
    chroot $HOST /usr/bin/openssl req -new -sha256 -key $CERTDIR/internal.key -out /tmp/tmpint.csr -subj "/C=US/ST=Colorado/L=Denver/O=Kensington Technology Associates, Limited/CN=localhost/emailAddress=info@knowledgekta.com"
    chroot $HOST /usr/bin/openssl x509 -req -days 3650 -in /tmp/tmpint.csr -signkey $CERTDIR/internal.key -out $CERTDIR/internal.cer
    chroot $HOST /usr/bin/openssl x509 -in ${CERTDIR}/internal.cer -pubkey -noout > ${HOST}${CERTDIR}/internal.pem
    chmod 600 ${HOST}${CERTDIR}/internal.key ${HOST}${CERTDIR}/internal.cer
  fi

  # Check for extracted public key
  if [[ -f ${HOST}${CERTDIR}/internal.key && -f ${HOST}${CERTDIR}/internal.cer && ! -f ${HOST}${CERTDIR}/internal.pem ]]; then
    echo "Missing internal.pem.  Extracting it from internal.cer"
    chroot $HOST /usr/bin/openssl x509 -in ${CERTDIR}/internal.cer -pubkey -noout > ${HOST}${CERTDIR}/internal.pem
  fi


  if [ -f $HOST/etc/systemd/system/afb-server.service ]; then
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

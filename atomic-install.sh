#!/bin/bash

ETCDIR=/etc/kentech/221b
CERTDIR=$ETCDIR/certificates
CFGFILE=221b-server.conf

if [ ! -d ${HOST}${ETCDIR} ]; then
  echo Creating $ETCDIR
  mkdir -p ${HOST}${ETCDIR}
fi

if [ ! -d ${HOST}${CERTDIR} ]; then
  echo Creating $CERTDIR
  mkdir -p ${HOST}${CERTDIR}
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
  chroot $HOST /usr/bin/docker stop $NAME >/dev/null
fi

# Remove existing container, if present
chroot $HOST /usr/bin/docker ps -a -f name=$NAME | grep -q ${NAME}$
if [ $? -eq 0 ]; then
  echo Removing existing $NAME container
  chroot $HOST /usr/bin/docker rm $NAME >/dev/null
fi

# Create network '221b-network' if not already there
chroot $HOST /usr/bin/docker network ls  | awk '{print $2}' | grep -q ^221b-network$
if [ $? -ne 0 ]; then
  echo Creating bridge network 221b-network
  chroot $HOST /usr/bin/docker network create --subnet 172.31.255.240/28 --gateway 172.31.255.241 -d bridge 221b-network >/dev/null
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
  chmod 600 ${HOST}${CERTDIR}/internal.key ${HOST}${CERTDIR}/internal.cer
  chroot $HOST /usr/bin/openssl x509 -in ${HOST}${CERTDIR}/internal.cer -pubkey -noout > ${HOST}${CERTDIR}/internal.pem
fi

# Check for extracted public key
if [[ -f ${HOST}${CERTDIR}/internal.key && -f ${HOST}${CERTDIR}/internal.cer && ! -f ${HOST}${CERTDIR}/internal.pem ]]; then
  echo "Missing internal.pem.  Extracting it from internal.cer"
  chroot $HOST /usr/bin/openssl x509 -in ${HOST}${CERTDIR}/internal.cer -pubkey -noout > ${HOST}${CERTDIR}/internal.pem
fi

# Create container
echo Creating container $NAME from image $IMAGE
chroot $HOST /usr/bin/docker create --name $NAME --network 221b-network --ip 172.31.255.243 --add-host 221b-mongo:172.31.255.242 -v /etc/kentech:/etc/kentech:ro -v /var/kentech:/var/kentech:rw,z -e SYSTEMD=1 $IMAGE >/dev/null

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

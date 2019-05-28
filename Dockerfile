FROM afb-server-base:latest
WORKDIR /opt/kentech/afb-server/bin
ARG AFBDEBUG
ENV NODE_ENV="production"
ENV AFBDEBUG=$AFBDEBUG
EXPOSE 3002
VOLUME [ "/etc/kentech", "/var/kentech" ]
# We will use systemd for logging, so we don't specify /var/log in 'VOLUME'
CMD ["node", "server.js"]

#our atomic labels
LABEL INSTALL="docker run --rm --name afb-server-installer-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=afb-server IMAGE /bin/atomic-install.sh"
LABEL UNINSTALL="docker run --rm --name afb-server-uninstaller-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=afb-server IMAGE /bin/atomic-uninstall.sh"
LABEL RUN="docker run --rm --name afb-server-run-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=afb-server IMAGE /bin/atomic-run.sh"
LABEL STOP="docker run --rm --name afb-server-stop-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=afb-server IMAGE /bin/atomic-stop.sh"

#Install the rest of our files
COPY atomic-*.sh /bin/
COPY atomic-afb-server.service /usr/lib/systemd/system/afb-server.service
COPY node_modules /opt/kentech/afb-server/bin/node_modules/
COPY afb-server.conf.default dist/ LICENSE.txt /opt/kentech/afb-server/bin/

#install our rpm dependencies
ARG CACHE_DATE=2016-01-01
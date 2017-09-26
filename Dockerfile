FROM centos:centos7
WORKDIR /opt/kentech/221b-server/bin
ENV NODE_ENV="production"
EXPOSE 3002
VOLUME [ "/etc/kentech", "/var/kentech" ]
# We will use systemd for logging, so we don't specify /var/log in 'VOLUME'
CMD ["node", "server.js"]

#our atomic labels
LABEL INSTALL="docker run --rm --name 221b-server-installer-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=221b-server IMAGE /bin/atomic-install.sh"
LABEL UNINSTALL="docker run --rm --name 221b-server-uninstaller-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=221b-server IMAGE /bin/atomic-uninstall.sh"
LABEL RUN="docker run --rm --name 221b-server-run-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=221b-server IMAGE /bin/atomic-run.sh"
LABEL STOP="docker run --rm --name 221b-server-stop-tmp --privileged -v /:/host -e HOST=/host -e IMAGE=IMAGE -e NAME=221b-server IMAGE /bin/atomic-stop.sh"

#Install the rest of our files
COPY 221b-server.conf /opt/kentech/221b-server/bin/
COPY atomic-*.sh /bin/
COPY atomic-221b-server.service /usr/lib/systemd/system/221b-server.service
COPY models /opt/kentech/221b-server/bin/models/
COPY node_modules /opt/kentech/221b-server/bin/node_modules/
COPY *.js* 221b_worker.py *.so 221b.license /opt/kentech/221b-server/bin/

#install our rpm dependencies
ARG CACHE_DATE=2016-01-01
RUN yum clean all; \
yum update -y; \
curl http://kentechrepo/yumrepo/221b_1.0.0_release/221b-1.0.0-release.repo > /etc/yum.repos.d/221b-1.0.0-release.repo; \
yum install -y nodejs kta-python-magic kta-python-Pillow kta-python-rarfile ghostscript poppler-utils libjpeg-turbo openjpeg unzip unrar; \
rm -f /etc/yum.repos.d/221b-1.0.0-release.repo; \
yum clean all; \
rm -rf /var/cache/yum;
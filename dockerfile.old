FROM centos:centos7
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
#COPY afb-server.conf.default *.js *.js.map worker_stub.py feeder_stub.py *.so LICENSE.txt /opt/kentech/afb-server/bin/
COPY afb-server.conf.default *.js *.js.map *.py *.so LICENSE.txt /opt/kentech/afb-server/bin/

#install our rpm dependencies
ARG CACHE_DATE=2016-01-01
RUN \
echo 172.16.0.57 kentechrepo >> /etc/hosts \
&& cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.orig \
&& /bin/sed -i'' 's/mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/CentOS-Base.repo \
&& /bin/sed -i'' 's/#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/kentechrepo/g' /etc/yum.repos.d/CentOS-Base.repo \
&& yum clean all \
&& yum update -y --disableplugin=fastestmirror \
&& rpm --import http://kentechrepo/yumrepo/afb_1.0.0_signed/afb-1.x.key \
&& rpm --import http://kentechrepo/yumrepo/afb_1.0.0_signed/NODESOURCE-GPG-SIGNING-KEY-EL \
&& curl http://kentechrepo/yumrepo/afb_1.0.0_signed/afb-1.0.0-signed.repo > /etc/yum.repos.d/afb-1.0.0-signed.repo \
&& yum install -y --disableplugin=fastestmirror nodejs ghostscript poppler-utils libjpeg-turbo openjpeg unzip unrar python-requests python2-crypto python-setuptools libreoffice \
&& yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
&& yum install -y --disableplugin=fastestmirror python-pip kta-python-systemd \
&& pip install --upgrade pip \
&& pip install requests \
&& pip install requests-futures \
&& pip install Pillow \
&& pip install rarfile \
&& pip install python-magic \
&& pip uninstall -y pip \
&& yum erase -y epel-release python-pip \
&& rm -f /etc/yum.repos.d/afb-1.0.0-signed.repo \
&& yum clean all \
&& rm -rf /var/cache/yum \
&& mv -f /etc/yum.repos.d/CentOS-Base.repo.orig /etc/yum.repos.d/CentOS-Base.repo \
&& H=`grep -v kentechrepo /etc/hosts` \
&& echo -n $H > /etc/hosts;
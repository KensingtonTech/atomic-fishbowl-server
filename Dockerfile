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
&& yum groupinstall -y Development\ Tools \
&& /bin/sed -i'' 's/mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/CentOS-Base.repo \
&& /bin/sed -i'' 's/#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/kentechrepo/g' /etc/yum.repos.d/CentOS-Base.repo \
&& yum clean all \
&& yum update -y --disableplugin=fastestmirror \
&& rpm --import http://kentechrepo/yumrepo/afb_1.0.0_signed/afb-1.x.key \
&& rpm --import http://kentechrepo/yumrepo/afb_1.0.0_signed/NODESOURCE-GPG-SIGNING-KEY-EL \
&& curl http://kentechrepo/yumrepo/afb_1.0.0_signed/afb-1.0.0-signed.repo > /etc/yum.repos.d/afb-1.0.0-signed.repo \
&& yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
&& yum install -y --disableplugin=fastestmirror nodejs ghostscript poppler-utils libjpeg-turbo openjpeg unzip unrar libreoffice python36 python36-devel \
&& curl -L https://bootstrap.pypa.io/get-pip.py > /root/get-pip.py \
&& ln -s python3.6 /usr/bin/python3 \
&& python3 /root/get-pip.py \
&& rm -f /root/get-pip.py \
&& pip3 install --upgrade pip \
&& pip3 install requests requests-futures crypto pycrypto Pillow rarfile python-magic \
&& pip3 uninstall -y pip \
&& yum erase -y epel-release python36-devel \
&& rm -f /etc/yum.repos.d/afb-1.0.0-signed.repo \
&& yum clean all \
&& rm -rf /var/cache/yum \
&& mv -f /etc/yum.repos.d/CentOS-Base.repo.orig /etc/yum.repos.d/CentOS-Base.repo \
&& yum grouperase -y Development\ Tools \
&& H=`grep -v kentechrepo /etc/hosts` \
&& echo -n $H > /etc/hosts;
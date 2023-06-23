#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

if ! grep -q '^alias ll=' ~/.bashrc; then echo "alias ll='/bin/ls --color -lah'" >> ~/.bashrc; . ~/.bashrc; fi

dnf makecache
dnf install -y epel-release ; dnf makecache
dnf upgrade -y epel-release ; dnf makecache
dnf install -y dnf-plugins-core
dnf config-manager --set-enabled powertools
dnf makecache
dnf upgrade -y

yum install -y openssl-libs
yum install -y openssl
yum install -y openssl-devel lksctp-tools-devel lksctp-tools

yum install -y gcc cpp gcc-c++ libstdc++-devel make m4 libtool pkgconfig groff-base \
  glibc-devel glib2-devel systemd-devel libuuid-devel \
  ncurses-devel ncurses elfutils-libelf-devel elfutils-devel libselinux-devel \
  libcom_err-devel libverto-devel keyutils-libs-devel krb5-devel libkadm5 libsepol-devel \
  redhat-rpm-config rpm-build rpmdevtools cpio wget ca-certificates curl \
  xz xz-devel bzip2 bzip2-devel gzip zlib-devel tar unzip zip \
  binutils util-linux findutils diffutils shadow-utils passwd \
  socat ethtool iptables ebtables ipvsadm ipset psmisc \
  bash-completion conntrack-tools iproute nfs-utils net-tools \
  authconfig libpwquality pam-devel pam audit which file sed gawk grep less \
  patch crontabs cronie info man-db lsof lshw dmidecode pciutils-libs pciutils yum-utils createrepo_c

yum install -y perl perl-devel perl-libs perl-Env perl-ExtUtils-Embed perl-IPC-Cmd \
  perl-ExtUtils-Install perl-ExtUtils-MakeMaker perl-ExtUtils-Manifest \
  perl-ExtUtils-ParseXS perl-Git perl-JSON perl-libwww-perl perl-podlators

yum install -y glibc-devel glibc-headers libxml2-devel libxslt-devel gd-devel \
  perl-devel perl bc net-snmp-libs net-snmp-agent-libs net-snmp-devel libnl3-devel libnl3

yum install -y asciidoc audit-libs-devel bash bc binutils binutils-devel bison bzip2 \
  diffutils elfutils-devel findutils flex gawk gcc gettext git gzip hmaccalc hostname \
  java-devel kmod libcap-devel m4 make ncurses-devel net-tools newt-devel numactl-devel \
  openssl openssl-devel patch pciutils-devel perl-ExtUtils-Embed perl-Carp perl-devel \
  perl-generators perl-interpreter python3-devel python3-docutils python3-sphinx \
  redhat-rpm-config rsync sh-utils tar xmlto xz xz-devel zlib-devel

yum install -y systemd-devel net-snmp-devel libnfnetlink-devel libnfnetlink file-devel file
yum install -y nftables-devel nftables
yum install -y iptables-devel iptables
yum install -y ipset-devel ipset
yum install -y rsyslog logrotate

/sbin/ldconfig >/dev/null 2>&1

echo
echo ' preinstall done'
echo









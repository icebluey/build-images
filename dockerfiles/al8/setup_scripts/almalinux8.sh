#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

_install_pre_el8() {
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    yum makecache
    yum install -y bash wget ca-certificates curl
    [[ -f /usr/bin/ln ]] && ln -svf bash /bin/sh
    wget -c -t 9 -T 9 "https://raw.githubusercontent.com/icebluey/pre-build/master/el8/.preinstall-el8"
    bash .preinstall-el8
    cd /tmp
    rm -fr "${_tmp_dir}"
}
_install_pre_el8

umask 022
CFLAGS='-O2 -fexceptions -g -grecord-gcc-switches -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fstack-protector-strong -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection'
export CFLAGS
CXXFLAGS='-O2 -fexceptions -g -grecord-gcc-switches -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fstack-protector-strong -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection'
export CXXFLAGS
LDFLAGS='-Wl,-z,relro -Wl,--as-needed -Wl,-z,now'
export LDFLAGS
_ORIG_LDFLAGS="${LDFLAGS}"
CC=gcc
export CC
CXX=g++
export CXX
/sbin/ldconfig

set -e

_strip_files() {
    if [[ "$(pwd)" = '/' ]]; then
        echo
        printf '\e[01;31m%s\e[m\n' "Current dir is '/'"
        printf '\e[01;31m%s\e[m\n' "quit"
        echo
        exit 1
    else
        rm -fr lib64
        rm -fr lib
        chown -R root:root ./
    fi
    find usr/ -type f -iname '*.la' -delete
    if [[ -d usr/share/man ]]; then
        find -L usr/share/man/ -type l -exec rm -f '{}' \;
        sleep 2
        find usr/share/man/ -type f -iname '*.[1-9]' -exec gzip -f -9 '{}' \;
        sleep 2
        find -L usr/share/man/ -type l | while read file; do ln -svf "$(readlink -s "${file}").gz" "${file}.gz" ; done
        sleep 2
        find -L usr/share/man/ -type l -exec rm -f '{}' \;
    fi
    if [[ -d usr/lib/x86_64-linux-gnu ]]; then
        find usr/lib/x86_64-linux-gnu/ -type f \( -iname '*.so' -or -iname '*.so.*' \) | xargs --no-run-if-empty -I '{}' chmod 0755 '{}'
        find usr/lib/x86_64-linux-gnu/ -iname 'lib*.so*' -type f -exec file '{}' \; | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs --no-run-if-empty -I '{}' /usr/bin/strip '{}'
        find usr/lib/x86_64-linux-gnu/ -iname '*.so' -type f -exec file '{}' \; | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs --no-run-if-empty -I '{}' /usr/bin/strip '{}'
    fi
    if [[ -d usr/lib64 ]]; then
        find usr/lib64/ -type f \( -iname '*.so' -or -iname '*.so.*' \) | xargs --no-run-if-empty -I '{}' chmod 0755 '{}'
        find usr/lib64/ -iname 'lib*.so*' -type f -exec file '{}' \; | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs --no-run-if-empty -I '{}' /usr/bin/strip '{}'
        find usr/lib64/ -iname '*.so' -type f -exec file '{}' \; | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs --no-run-if-empty -I '{}' /usr/bin/strip '{}'
    fi
    if [[ -d usr/sbin ]]; then
        find usr/sbin/ -type f -exec file '{}' \; | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs --no-run-if-empty -I '{}' /usr/bin/strip '{}'
    fi
    if [[ -d usr/bin ]]; then
        find usr/bin/ -type f -exec file '{}' \; | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs --no-run-if-empty -I '{}' /usr/bin/strip '{}'
    fi
    echo
}

_build_zlib() {
    /sbin/ldconfig
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    _zlib_ver="$(wget -qO- 'https://www.zlib.net/' | grep 'zlib-[1-9].*\.tar\.' | sed -e 's|"|\n|g' | grep '^zlib-[1-9]' | sed -e 's|\.tar.*||g' -e 's|zlib-||g' | sort -V | uniq | tail -n 1)"
    wget -c -t 9 -T 9 "https://www.zlib.net/zlib-${_zlib_ver}.tar.gz"
    tar -xof zlib-*.tar.*
    sleep 1
    rm -f zlib-*.tar*
    cd zlib-*
    ./configure --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include --sysconfdir=/etc --64
    make -j2 all
    rm -fr /tmp/zlib
    make DESTDIR=/tmp/zlib install
    cd /tmp/zlib
    _strip_files
    install -m 0755 -d usr/local/private
    cp -af usr/lib64/*.so* usr/local/private/
    /bin/rm -f /usr/lib64/libz.so*
    /bin/rm -f /usr/lib64/libz.a
    sleep 2
    /bin/cp -afr * /
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/zlib
    /sbin/ldconfig
}

_build_lz4() {
    /sbin/ldconfig
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    git clone --recursive "https://github.com/lz4/lz4.git"
    cd lz4
    rm -fr .git
    sed '/^PREFIX/s|= .*|= /usr|g' -i Makefile
    sed '/^LIBDIR/s|= .*|= /usr/lib64|g' -i Makefile
    sed '/^prefix/s|= .*|= /usr|g' -i Makefile
    sed '/^libdir/s|= .*|= /usr/lib64|g' -i Makefile
    sed '/^PREFIX/s|= .*|= /usr|g' -i lib/Makefile
    sed '/^LIBDIR/s|= .*|= /usr/lib64|g' -i lib/Makefile
    sed '/^prefix/s|= .*|= /usr|g' -i lib/Makefile
    sed '/^libdir/s|= .*|= /usr/lib64|g' -i lib/Makefile
    sed '/^PREFIX/s|= .*|= /usr|g' -i programs/Makefile
    sed '/^LIBDIR/s|= .*|= /usr/lib64|g' -i programs/Makefile
    sed '/^prefix/s|= .*|= /usr|g' -i programs/Makefile
    sed '/^libdir/s|= .*|= /usr/lib64|g' -i programs/Makefile
    LDFLAGS='' ; LDFLAGS="${_ORIG_LDFLAGS}"' -Wl,-rpath,\$$ORIGIN' ; export LDFLAGS
    make -j2 prefix=/usr libdir=/usr/lib64
    rm -fr /tmp/lz4
    make install DESTDIR=/tmp/lz4
    cd /tmp/lz4
    _strip_files
    find usr/lib64/ -type f -iname '*.so*' | xargs -I '{}' chrpath -r '$ORIGIN' '{}'
    install -m 0755 -d usr/local/private
    cp -af usr/lib64/*.so* usr/local/private/
    sleep 2
    /bin/cp -afr * /
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/lz4
    /sbin/ldconfig
}

_build_zstd() {
    /sbin/ldconfig
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    git clone --recursive "https://github.com/facebook/zstd.git"
    cd zstd
    rm -fr .git
    sed '/^PREFIX/s|= .*|= /usr|g' -i Makefile
    sed '/^LIBDIR/s|= .*|= /usr/lib64|g' -i Makefile
    sed '/^prefix/s|= .*|= /usr|g' -i Makefile
    sed '/^libdir/s|= .*|= /usr/lib64|g' -i Makefile
    sed '/^PREFIX/s|= .*|= /usr|g' -i lib/Makefile
    sed '/^LIBDIR/s|= .*|= /usr/lib64|g' -i lib/Makefile
    sed '/^prefix/s|= .*|= /usr|g' -i lib/Makefile
    sed '/^libdir/s|= .*|= /usr/lib64|g' -i lib/Makefile
    sed '/^PREFIX/s|= .*|= /usr|g' -i programs/Makefile
    sed '/^LIBDIR/s|= .*|= /usr/lib64|g' -i programs/Makefile
    sed '/^prefix/s|= .*|= /usr|g' -i programs/Makefile
    sed '/^libdir/s|= .*|= /usr/lib64|g' -i programs/Makefile
    LDFLAGS='' ; LDFLAGS="${_ORIG_LDFLAGS}"' -Wl,-rpath,\$$OOORIGIN' ; export LDFLAGS
    make -j2 prefix=/usr libdir=/usr/lib64
    rm -fr /tmp/zstd
    make install DESTDIR=/tmp/zstd
    cd /tmp/zstd
    _strip_files
    find usr/lib64/ -type f -iname '*.so*' | xargs -I '{}' chrpath -r '$ORIGIN' '{}'
    install -m 0755 -d usr/local/private
    cp -af usr/lib64/*.so* usr/local/private/
    sleep 2
    /bin/cp -afr * /
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/zstd
    /sbin/ldconfig
}

_build_libedit() {
    /sbin/ldconfig >/dev/null 2>&1
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    _libedit_ver="$(wget -qO- 'https://www.thrysoee.dk/editline/' | grep libedit-[1-9].*\.tar | sed 's|"|\n|g' | grep '^libedit-[1-9]' | sed -e 's|\.tar.*||g' -e 's|libedit-||g' | sort -V | uniq | tail -n 1)"
    wget -c -t 9 -T 9 "https://www.thrysoee.dk/editline/libedit-${_libedit_ver}.tar.gz"
    tar -xof libedit-*.tar.*
    sleep 1
    rm -f libedit-*.tar*
    cd libedit-*
    sed -i "s/lncurses/ltinfo/" configure
    LDFLAGS='' ; LDFLAGS="${_ORIG_LDFLAGS}"' -Wl,-rpath,\$$ORIGIN' ; export LDFLAGS
    ./configure \
    --build=x86_64-linux-gnu \
    --host=x86_64-linux-gnu \
    --prefix=/usr \
    --libdir=/usr/lib64 \
    --includedir=/usr/include \
    --sysconfdir=/etc \
    --enable-shared --enable-static \
    --enable-widec
    sleep 1
    make -j2 all
    rm -fr /tmp/libedit
    make install DESTDIR=/tmp/libedit
    cd /tmp/libedit
    _strip_files
    install -m 0755 -d usr/local/private
    cp -af usr/lib64/*.so* usr/local/private/
    rm -f /usr/lib64/libedit.*
    sleep 2
    /bin/cp -afr * /
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/libedit
    /sbin/ldconfig
}

_build_pcre2() {
    /sbin/ldconfig
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    _pcre2_ver="$(wget -qO- 'https://github.com/PCRE2Project/pcre2/releases' | grep -i 'pcre2-[1-9]' | sed 's|"|\n|g' | grep -i '^/PCRE2Project/pcre2/tree' | sed 's|.*/pcre2-||g' | sed 's|\.tar.*||g' | grep -ivE 'alpha|beta|rc' | sort -V | uniq | tail -n 1)"
    wget -c -t 9 -T 9 "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${_pcre2_ver}/pcre2-${_pcre2_ver}.tar.bz2"
    tar -xof pcre2-*.tar.*
    sleep 1
    rm -f pcre2-*.tar*
    cd pcre2-*
    LDFLAGS='' ; LDFLAGS="${_ORIG_LDFLAGS}"' -Wl,-rpath,\$$ORIGIN' ; export LDFLAGS
    ./configure \
    --build=x86_64-linux-gnu --host=x86_64-linux-gnu \
    --enable-shared --enable-static \
    --enable-pcre2-8 --enable-pcre2-16 --enable-pcre2-32 \
    --enable-jit \
    --enable-pcre2grep-libz \
    --enable-pcre2grep-libbz2 \
    --enable-pcre2test-libedit \
    --enable-unicode \
    --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include --sysconfdir=/etc
    sed 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' -i libtool
    make -j2 all
    rm -fr /tmp/pcre2
    make install DESTDIR=/tmp/pcre2
    cd /tmp/pcre2
    rm -fr usr/share/doc/pcre2/html
    _strip_files
    install -m 0755 -d usr/local/private
    cp -af usr/lib64/*.so* usr/local/private/
    sleep 2
    /bin/cp -afr * /
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/pcre2
    /sbin/ldconfig
}

_build_openssl111() {
    /sbin/ldconfig
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    _openssl111_ver="$(wget -qO- 'https://www.openssl.org/source/' | grep 'href="openssl-1.1.1' | sed 's|"|\n|g' | grep -i '^openssl-1.1.1.*\.tar\.gz$' | cut -d- -f2 | sed 's|\.tar.*||g' | sort -V | uniq | tail -n 1)"
    wget -c -t 9 -T 9 "https://www.openssl.org/source/openssl-${_openssl111_ver}.tar.gz"
    tar -xof openssl-*.tar*
    sleep 1
    rm -f openssl-*.tar*
    cd openssl-*
    # Only for debian/ubuntu
    #sed '/define X509_CERT_FILE .*OPENSSLDIR "/s|"/cert.pem"|"/certs/ca-certificates.crt"|g' -i include/internal/cryptlib.h
    sed '/install_docs:/s| install_html_docs||g' -i Configurations/unix-Makefile.tmpl
    LDFLAGS='' ; LDFLAGS="${_ORIG_LDFLAGS}"' -Wl,-rpath,\$$ORIGIN' ; export LDFLAGS
    HASHBANGPERL=/usr/bin/perl
    ./Configure \
    --prefix=/usr \
    --libdir=/usr/lib64 \
    --openssldir=/etc/pki/tls \
    enable-ec_nistp_64_gcc_128 \
    zlib enable-tls1_3 threads \
    enable-camellia enable-seed \
    enable-rfc3779 enable-sctp enable-cms \
    enable-md2 enable-rc5 \
    no-mdc2 no-ec2m \
    no-sm2 no-sm3 no-sm4 \
    shared linux-x86_64 '-DDEVRANDOM="\"/dev/urandom\""'
    perl configdata.pm --dump
    make -j2 all
    rm -fr /tmp/openssl111
    make DESTDIR=/tmp/openssl111 install_sw
    cd /tmp/openssl111
    # Only for debian/ubuntu
    #mkdir -p usr/include/x86_64-linux-gnu/openssl
    #chmod 0755 usr/include/x86_64-linux-gnu/openssl
    #install -c -m 0644 usr/include/openssl/opensslconf.h usr/include/x86_64-linux-gnu/openssl/
    sed 's|http://|https://|g' -i usr/lib64/pkgconfig/*.pc
    _strip_files
    install -m 0755 -d usr/local/private
    cp -af usr/lib64/*.so* usr/local/private/
    #rm -f /usr/lib64/libssl.*
    #rm -f /usr/lib64/libcrypto.*
    rm -fr /usr/include/openssl
    rm -fr /usr/include/x86_64-linux-gnu/openssl
    rm -fr /usr/local/openssl-1.1.1
    rm -f /etc/ld.so.conf.d/openssl-1.1.1.conf
    sleep 2
    /bin/cp -afr * /
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/openssl111
    /sbin/ldconfig
}

_build_openssl30quictls() {
    /sbin/ldconfig
    set -e
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    #_openssl30quictls_ver="$(wget -qO- 'https://github.com/quictls/openssl/branches/all/' | grep -i 'branch="OpenSSL-3\.0\..*quic"' | sed 's/"/\n/g' | grep -i '^openssl.*quic$' | sort -V | tail -n 1)"
    #git clone -b "${_openssl30quictls_ver}" 'https://github.com/quictls/openssl.git' 'openssl30quictls'
    mv -f /tmp/openssl30quictls-git.tar.gz ./
    tar -xof openssl30quictls-git.tar.gz
    sleep 1
    rm -f openssl30quictls-*.tar*
    cd openssl30quictls
    rm -fr .git
    # Only for debian/ubuntu
    #sed '/define X509_CERT_FILE .*OPENSSLDIR "/s|"/cert.pem"|"/certs/ca-certificates.crt"|g' -i include/internal/cryptlib.h
    sed '/install_docs:/s| install_html_docs||g' -i Configurations/unix-Makefile.tmpl
    LDFLAGS='' ; LDFLAGS="${_ORIG_LDFLAGS}"' -Wl,-rpath,\$$ORIGIN' ; export LDFLAGS
    HASHBANGPERL=/usr/bin/perl
    ./Configure \
    --prefix=/usr \
    --libdir=/usr/lib64 \
    --openssldir=/etc/pki/tls \
    enable-ec_nistp_64_gcc_128 \
    zlib enable-tls1_3 threads \
    enable-camellia enable-seed \
    enable-rfc3779 enable-sctp enable-cms \
    enable-md2 enable-rc5 enable-ktls \
    no-mdc2 no-ec2m \
    no-sm2 no-sm3 no-sm4 \
    shared linux-x86_64 '-DDEVRANDOM="\"/dev/urandom\""'
    perl configdata.pm --dump
    make -j2 all
    rm -fr /tmp/openssl30quictls
    make DESTDIR=/tmp/openssl30quictls install_sw
    cd /tmp/openssl30quictls
    # Only for debian/ubuntu
    #mkdir -p usr/include/x86_64-linux-gnu/openssl
    #chmod 0755 usr/include/x86_64-linux-gnu/openssl
    #install -c -m 0644 usr/include/openssl/opensslconf.h usr/include/x86_64-linux-gnu/openssl/
    sed 's|http://|https://|g' -i usr/lib64/pkgconfig/*.pc
    _strip_files
    install -m 0755 -d usr/local/private
    cp -af usr/lib64/*.so* usr/local/private/
    #rm -f /usr/lib64/libssl.*
    #rm -f /usr/lib64/libcrypto.*
    rm -fr /usr/include/openssl
    rm -fr /usr/include/x86_64-linux-gnu/openssl
    rm -fr /usr/local/openssl-1.1.1
    rm -f /etc/ld.so.conf.d/openssl-1.1.1.conf
    sleep 2
    /bin/cp -afr * /
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/openssl30quictls
    /sbin/ldconfig
}
_dl_openssl30quictls() {
    set -e
    cd /tmp
    rm -fr /tmp/openssl30quictls
    _openssl30quictls_ver="$(wget -qO- 'https://github.com/quictls/openssl/branches/all/' | grep -i 'branch="OpenSSL-3\.0\..*quic"' | sed 's/"/\n/g' | grep -i '^openssl.*quic$' | sort -V | tail -n 1)"
    git clone -b "${_openssl30quictls_ver}" 'https://github.com/quictls/openssl.git' 'openssl30quictls'
    rm -fr openssl30quictls/.git
    sleep 2
    tar -zcf openssl30quictls-git.tar.gz openssl30quictls
    sleep 2
    cd /tmp
    rm -fr /tmp/openssl30quictls
}
_dl_openssl30quictls

rm -fr /usr/local/private
_build_zlib
_build_lz4
_build_zstd
_build_libedit
_build_pcre2
#_build_openssl111
_build_openssl30quictls
echo
echo ' setup env done'
echo

_tmp_dir="$(mktemp -d)"
cd "${_tmp_dir}"
yum install -y linux-firmware
git clone 'git://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git'
sleep 2
cd linux-firmware
rm -fr Makefile.old Makefile.new
cp -fr Makefile Makefile.new
printf '\x23\x20\x54\x68\x69\x73\x20\x66\x69\x6C\x65\x20\x69\x6D\x70\x6C\x65\x6D\x65\x6E\x74\x73\x20\x74\x68\x65\x20\x47\x4E\x4F\x4D\x45\x20\x42\x75\x69\x6C\x64\x20\x41\x50\x49\x3A\x0A\x23\x20\x68\x74\x74\x70\x3A\x2F\x2F\x70\x65\x6F\x70\x6C\x65\x2E\x67\x6E\x6F\x6D\x65\x2E\x6F\x72\x67\x2F\x7E\x77\x61\x6C\x74\x65\x72\x73\x2F\x64\x6F\x63\x73\x2F\x62\x75\x69\x6C\x64\x2D\x61\x70\x69\x2E\x74\x78\x74\x0A\x0A\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x20\x3D\x20\x2F\x6C\x69\x62\x2F\x66\x69\x72\x6D\x77\x61\x72\x65\x0A\x0A\x61\x6C\x6C\x3A\x0A\x0A\x63\x68\x65\x63\x6B\x3A\x0A\x09\x2E\x2F\x63\x68\x65\x63\x6B\x5F\x77\x68\x65\x6E\x63\x65\x2E\x70\x79\x0A\x0A\x69\x6E\x73\x74\x61\x6C\x6C\x3A\x0A\x09\x6D\x6B\x64\x69\x72\x20\x2D\x70\x20\x24\x28\x44\x45\x53\x54\x44\x49\x52\x29\x24\x28\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x29\x0A\x09\x63\x70\x20\x2D\x66\x72\x20\x2A\x20\x24\x28\x44\x45\x53\x54\x44\x49\x52\x29\x24\x28\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x29\x0A\x09\x72\x6D\x20\x2D\x72\x66\x20\x24\x28\x44\x45\x53\x54\x44\x49\x52\x29\x24\x28\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x29\x2F\x75\x73\x62\x64\x75\x78\x0A\x09\x72\x6D\x20\x2D\x72\x66\x20\x24\x28\x44\x45\x53\x54\x44\x49\x52\x29\x24\x28\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x29\x2F\x63\x6F\x70\x79\x2D\x66\x69\x72\x6D\x77\x61\x72\x65\x2E\x73\x68\x0A\x09\x72\x6D\x20\x2D\x72\x66\x20\x24\x28\x44\x45\x53\x54\x44\x49\x52\x29\x24\x28\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x29\x2F\x4D\x61\x6B\x65\x66\x69\x6C\x65\x2E\x6F\x6C\x64\x0A\x09\x72\x6D\x20\x2D\x72\x66\x20\x24\x28\x44\x45\x53\x54\x44\x49\x52\x29\x24\x28\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x29\x2F\x4D\x61\x6B\x65\x66\x69\x6C\x65\x2E\x6E\x65\x77\x0A\x09\x66\x69\x6E\x64\x20\x24\x28\x44\x45\x53\x54\x44\x49\x52\x29\x24\x28\x46\x49\x52\x4D\x57\x41\x52\x45\x44\x49\x52\x29\x20\x5C\x28\x20\x2D\x6E\x61\x6D\x65\x20\x27\x57\x48\x45\x4E\x43\x45\x27\x20\x2D\x6F\x72\x20\x2D\x6E\x61\x6D\x65\x20\x27\x4C\x49\x43\x45\x4E\x53\x45\x2E\x2A\x27\x20\x2D\x6F\x72\x20\x5C\x0A\x09\x09\x2D\x6E\x61\x6D\x65\x20\x27\x4C\x49\x43\x45\x4E\x43\x45\x2E\x2A\x27\x20\x5C\x29\x20\x2D\x65\x78\x65\x63\x20\x72\x6D\x20\x2D\x2D\x20\x7B\x7D\x20\x5C\x3B\x0A' | dd seek=$((0x0)) conv=notrunc bs=1 of=Makefile.old
chmod 644 Makefile.old
rm -fr Makefile
sleep 2
cat Makefile.old > Makefile
make install
sleep 2
cd /tmp
rm -fr "${_tmp_dir}"
echo
echo ' Update Linux Firmware done'
echo
echo '##################################'
echo ' Clean cache'
echo '##################################'
yum clean all
/bin/rm -fr /var/cache/dnf
sleep 1
install -m 0755 -d /var/cache/dnf
/bin/rm -fr ~/.wget-hst*
find /var/log/ -type f -exec /bin/bash -c "/usr/bin/cat /dev/null > {}" \;
/bin/rm -fr /var/tmp/*
/bin/rm -fr /var/tmp/.[A-Za-z0-9]*
/bin/rm -fr /tmp/*
/bin/rm -fr /tmp/.[A-Za-z0-9]*
exit

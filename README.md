# Name
ngx_http_auth_basic_ldap - Enables **HTTP Basic Authentication** using **LDAP** as an authorization provider.

*This module is not distributed with the Nginx source.* See the [installation instructions](#installation).

# Installation

## Prerequisites
This module requires the C libraries for openssl and ldap. On ubuntu you can install them with the following command:

    apt-get install libssl-dev libldap2-dev

**NOTICE:** Other C libraries might be required by nginx core files.

## Compatibility
The following versions of Nginx should work with this module:
- >= 1.9.11

## Compiling
The following process will describe how to compile this module so you can use it with an already compiled nginx package. The example is for `ubuntu 16.04`, with nginx installed through `apt-get`, but it should be similar to any other distribution.

First you will have to find the configure arguments and version for your compiled nginx:

    ubuntu@hostname:~$ nginx -V
    nginx version: nginx/1.10.0 (Ubuntu)
    built with OpenSSL 1.0.2g-fips  1 Mar 2016
    TLS SNI support enabled
    configure arguments: --with-cc-opt='-g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-debug --with-pcre-jit --with-ipv6 --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_addition_module --with-http_dav_module --with-http_geoip_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module --with-http_v2_module --with-http_sub_module --with-http_xslt_module --with-stream --with-stream_ssl_module --with-mail --with-mail_ssl_module --with-threads

Grab the nginx source code:

    wget http://nginx.org/download/nginx-1.10.0.tar.gz
    tar xzf nginx-1.10.0.tar.gz
    cd nginx-1.10.0/

Compile the module:

    # configure it using the earlier retrieved configure arguments + the --add-dynamic-module argument
    ./configure --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' \
                --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now' \
                --prefix=/usr/share/nginx \
                --conf-path=/etc/nginx/nginx.conf \
                --http-log-path=/var/log/nginx/access.log \
                --error-log-path=/var/log/nginx/error.log \
                --lock-path=/var/lock/nginx.lock \
                --pid-path=/run/nginx.pid \
                --http-client-body-temp-path=/var/lib/nginx/body \
                --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
                --http-proxy-temp-path=/var/lib/nginx/proxy \
                --http-scgi-temp-path=/var/lib/nginx/scgi \
                --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
                --with-debug \
                --with-pcre-jit \
                --with-ipv6 \
                --with-http_ssl_module \
                --with-http_stub_status_module \
                --with-http_realip_module \
                --with-http_auth_request_module \
                --with-http_addition_module \
                --with-http_dav_module \
                --with-http_geoip_module \
                --with-http_gunzip_module \
                --with-http_gzip_static_module \
                --with-http_image_filter_module \
                --with-http_v2_module \
                --with-http_sub_module \
                --with-http_xslt_module \
                --with-stream \
                --with-stream_ssl_module \
                --with-mail \
                --with-mail_ssl_module \
                --with-threads \
                --add-dynamic-module=/path/to/ngx_http_auth_basic_ldap_module
    make modules

**IMPORTAT:** I ommited the `-fPIE` and `-pie` flags from `--with-cc-opt` and `--with-ld-opt` because our generated position independent code is gonna be used by a shared object.

A shared object will be generated at: `objs/ngx_http_auth_basic_ldap_module.so`. You will have to copy this module to modules folder: `/usr/share/nginx/modules`; and then to use [load_module](http://nginx.org/en/docs/ngx_core_module.html#load_module) directive: `load_module modules/ngx_http_auth_basic_ldap_module.so`.

### Compiling - general
Grab the nginx source code from [nginx.org](http://nginx.org/), for example, the version 1.11.3 (see [nginx compatibility](#compatibility)), and then build the source with this module:

    wget http://nginx.org/download/nginx-1.11.3.tar.gz
    tar xzf nginx-1.11.3.tar.gz
    cd nginx-1.11.2/

    # assuming that you will install nginx under /opt/nginx/.
    ./configure --prefix=/opt/nginx \
                --add-dynamic-module=/path/to/ngx_http_auth_basic_ldap_module

    make
    make install

After the compilation is finished you will be able to load the module dynamically with [load_module](http://nginx.org/en/docs/ngx_core_module.html#load_module) directive, for example:

    load_module /opt/nginx/modules/ngx_http_auth_basic_ldap_module.so

# Example configuration

    location / {
        auth_basic_ldap_realm "ldap";
        auth_basic_ldap_url "ldap://localhost:389";
        auth_basic_ldap_bind_dn 'cn="Common Name"';
        auth_basic_ldap_bind_password "bind-password";
        auth_basic_ldap_search_base "cn=users,dc=example,dc=com";
    }

# Directives

#### auth_basic_ldap_realm
>Syntax: **auth_basic_ldap_realm** *string* | off;
>
>Default: auth_basic_ldap_realm off;
>
>Context: location

Enables validation of user name and password using the “HTTP Basic Authentication” protocol with LDAP. The specified parameter is used as a *realm*. The special value *off* allows cancelling the effect of the *auth_basic_ldap_realm* directive inherited from the previous configuration level.

#### auth_basic_ldap_url
>Syntax: **auth_basic_ldap_url** *string*;
>
>Default: -
>
>Context: location

Specifies the url for the LDAP server.

#### auth_basic_ldap_bind_dn
>Syntax: **auth_basic_ldap_bind_dn** *string*;
>
>Default: -
>
>Context: location

Specifies the distinguished name for the LDAP root user.

#### auth_basic_ldap_bind_password
>Syntax: **auth_basic_ldap_bind_password** *string*;
>
>Default: -
>
>Context: location

Specifies the password for the LDAP root user.

#### auth_basic_ldap_search_base
>Syntax: **auth_basic_ldap_search_base** *string*;
>
>Default: -
>
>Context: location

Specifies the base DN for the search directory.

#### auth_basic_ldap_search_attr
>Syntax: **auth_basic_ldap_search_attr** *string*;
>
>Default: auth_basic_ldap_search_attr "uid";
>
>Context: location

Specifies the attribute to search by.

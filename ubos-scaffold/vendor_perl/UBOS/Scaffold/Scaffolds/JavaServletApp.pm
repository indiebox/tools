#!/usr/bin/perl
#
# A scaffold for Java Servlet app packages on UBOS.
#
# This file is part of ubos-scaffold.
# (C) 2017 Indie Computing Corp.
#
# ubos-scaffold is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ubos-scaffold is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ubos-scaffold.  If not, see <http://www.gnu.org/licenses/>.
#

use strict;
use warnings;

package UBOS::Scaffold::Scaffolds::JavaServletApp;

##
# Declare which parameters should be provided for this scaffold.
sub pars {
    return [
        {
            'name'        => 'name',
            'description' => <<DESC
Name of the accessory package
DESC
        },
        {
            'name'        => 'developer',
            'description' => <<DESC
URL of the developer, such as your company URL
DESC
        },
        {
            'name'        => 'url',
            'description' => <<DESC
URL of the package, such as a product information page on your company website
DESC
        },
        {
            'name'        => 'description',
            'description' => <<DESC
One-line description of your package, which will be shown to the user when
they ask pacman about your package (-i flag to pacman)
DESC
        },
        {
            'name'        => 'license',
            'description' => <<DESC
License of your package, such as GPL, Apache, or Proprietary
DESC
        },
        {
            'name'        => 'groupId',
            'description' => <<DESC
Maven GroupId of your project, such as com.example.greatestever
DESC
        }
    ];
}

##
# Do the generation
# $pars: the parameters to use
# $dir: the output directory
sub generate {
    my $pars = shift;
    my $dir  = shift;

    my $pkgBuild = <<END;
#
# PKGBUILD for package $pars->{name}, generated by ubos-scaffold.
# For the syntax of this file, please refer to the description on the
# Arch Linux wiki here: https://wiki.archlinux.org/index.php/PKGBUILD
#

developer='$pars->{developer}'
url='$pars->{url}'
maintainer='\${developer}'
pkgname='$pars->{name}'
pkgver=0.1
pkgrel=1
pkgdesc='$pars->{description}'
arch=('any')
license=('$pars->{license}')

# Your project's maven groupId
_groupId='$pars->{groupId}'

makedepends=(
    'maven'
    'jdk8-openjdk'
)
depends=(
    # Insert your UBOS package dependencies here as a bash array, like this:
    #     'java-runtime' 'mysql-connector-java'
    # and close with a parenthesis
)
backup=(
    # List any config files your package uses that should NOT be overridden
    # upon the next package update if the user has modified them.
)
source=(
    # Insert URLs to the source(s) of your code here, usually one or more tar files
    # or such, like this:
    #     "https://download.nextcloud.com/server/releases/nextcloud-\${pkgver}.tar.bz2"
)
sha512sums=(
    # List the checksums for one source at a time, same sequence as the in
    # the sources array, like this:
    #     '1c1e59d3733d4c1073c19f54c8eda48f71a7f9e8db74db7ab761fcd950445f7541bce5d9ac800238ab7099ff760cb51bd59b7426020128873fa166870c58f125'
)

# If your package requires compilation, uncomment this build() function
# and insert your build code.
# build () {
#     echo -n 'Build starts in directory:'
#     pwd
# }

build() {
    cd \${startdir}/maven
    sed -e "s/PKGBUILD_VERSION/\${pkgver}/" pom.xml.tmpl > pom.xml
    mvn clean install \\\${MVN_OPTS}
}

package() {
# Manifest
    mkdir -p \${pkgdir}/var/lib/ubos/manifests
    install -m0644 \${startdir}/ubos-manifest.json \${pkgdir}/var/lib/ubos/manifests/\${pkgname}.json

# Icons
    mkdir -p \${pkgdir}/srv/http/_appicons/\${pkgname}
    install -m644 \${startdir}/appicons/{72x72,144x144}.png \${pkgdir}/srv/http/_appicons/\${pkgname}/

# Data
    mkdir -p \${pkgdir}/var/lib/\${pkgname}

# Code
    mkdir -p \${pkgdir}/usr/share/\${pkgname}
    # install your code here, such as:
    #     install -m0755 \${startdir}/my-\${pkgname}-script \${pkgdir}/usr/bin/

# Code
    install -m644 -D \${startdir}/maven/target/\${pkgname}-\${pkgver}.war \
                     \${pkgdir}/usr/lib/java/\${_groupId//.//}/\${pkgname}/\${pkgver}/\${pkgname}-\${pkgver}.war

# Templates, with package/module names and versions replaced
    mkdir -p \${pkgdir}/usr/share/\${pkgname}/tmpl
    install -m644 \${startdir}/tmpl/context.xml.tmpl \${pkgdir}/usr/share/\${pkgname}/tmpl/
    install -m644 \${startdir}/tmpl/htaccess.tmpl    \${pkgdir}/usr/share/\${pkgname}/tmpl/

    groupId=\${_groupId//./\\/}

    sed -i -e "s/\\\${pkgname}/\${pkgname}/g" \${pkgdir}/usr/share/\${pkgname}/tmpl/context.xml.tmpl
    sed -i -e "s/\\\${pkgver}/\${pkgver}/g"   \${pkgdir}/usr/share/\${pkgname}/tmpl/context.xml.tmpl
    sed -i -e "s/\\\${groupId}/\${groupId}/g" \${pkgdir}/usr/share/\${pkgname}/tmpl/context.xml.tmpl

# SQL
    mkdir -p \${pkgdir}/usr/share/\${pkgname}/sql
    install -m755 \${startdir}/sql/create.sql \${pkgdir}/usr/share/\${pkgname}/sql/
}
END

    my $manifest = <<END;
{
    "type" : "app",

    "roles" : {
        "apache2" : {
            "defaultcontext" : "/$pars->{name}",
            "apache2modules" : [
                "proxy",
                "proxy_ajp"
            ],
            "appconfigitems" : [
                {
                    "type" : "file",
                    "name" : "\${appconfig.apache2.appconfigfragmentfile}",
                    "template"     : "tmpl/htaccess.tmpl",
                    "templatelang" : "varsubst"
                }
            ]
        },
        "tomcat8" : {
            "defaultcontext" : "/$pars->{name}",
            "appconfigitems" : [
                {
                    "type"         : "file",
                    "name"         : "\${appconfig.tomcat8.contextfile}",
                    "template"     : "tmpl/context.xml.tmpl",
                    "templatelang" : "varsubst"
                }
            ]
        },
        "mysql" : {
            "appconfigitems" : [
                {
                    "type"             : "database",
                    "name"             : "maindb",
                    "retentionpolicy"  : "keep",
                    "retentionbucket"  : "maindb",
                    "privileges"       : "select, insert"
                }
            ],
            "installers" : [
                {
                    "name"   : "maindb",
                    "type"   : "sqlscript",
                    "source" : "sql/create.sql"
                }
            ]
        }
    }
}

END

    my $htAccessTmpl = <<END;
ProxyPass /robots.txt !
ProxyPass /favicon.ico !
ProxyPass /sitemap.xml !
ProxyPass /.well-known !
ProxyPass /_common !
ProxyPass /_errors !

ProxyPass \${appconfig.contextorslash} ajp://127.0.0.1:8009\${appconfig.contextorslash}
ProxyPassReverse \${appconfig.contextorslash} ajp://127.0.0.1:8009\${appconfig.contextorslash}
END

    my $contextTmpl = <<END;
<?xml version="1.0" encoding="UTF-8"?>
<Context path="\${appconfig.context}"
         antiResourceLocking="true"
         cookies="false"
         docBase="/usr/lib/java/\${groupId}/\${pkgname}/\${pkgver}/\${pkgname}-\${pkgver}.war">

  <Resource auth="Container"
            type="javax.sql.DataSource"
            driverClassName="com.mysql.jdbc.Driver"
            name="jdbc/maindb"
            url="jdbc:mysql://\${appconfig.mysql.dbhost.maindb}/\${appconfig.mysql.dbname.maindb}"
            username="\${appconfig.mysql.dbuser.maindb}"
            password="\${escapeDquote( appconfig.mysql.dbusercredential.maindb )}"
            maxActive="20"
            maxIdle="10"
            maxWait="-1"/>
</Context>
END

    my $sql = <<END;
# The SQL to be executed to initialize the MySQL database upon first install
# Insert here ...
END

    UBOS::Utils::mkdir( "$dir/appicons" );
    UBOS::Utils::mkdir( "$dir/sql" );
    UBOS::Utils::mkdir( "$dir/tmpl" );

    UBOS::Utils::saveFile( "$dir/PKGBUILD",              $pkgBuild,     0644 );
    UBOS::Utils::saveFile( "$dir/ubos-manifest.json",    $manifest,     0644 );

    UBOS::Scaffold::ScaffoldUtils::copyIcons( "$dir/appicons" );

    UBOS::Utils::saveFile( "$dir/sql/create.sql",        $sql,          0644 );

    UBOS::Utils::saveFile( "$dir/tmpl/htaccess.tmpl",    $htAccessTmpl, 0644 );
    UBOS::Utils::saveFile( "$dir/tmpl/context.xml.tmpl", $contextTmpl,  0644 );
}

##
# Return help text.
# return: help text
sub help {
    return 'Java servlet app deployed to Tomcat';
}
1;

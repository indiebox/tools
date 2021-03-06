#!/usr/bin/perl
#
# Functionality common the Scaffolds.
#
# Copyright (C) 2017 and later, Indie Computing Corp. All rights reserved. License: see package.
#

use strict;
use warnings;

package UBOS::Scaffold::AbstractScaffold;

use fields;

use UBOS::Logging;
use UBOS::Scaffold::ScaffoldUtils;

####
# Constructor
sub new {
    my $self = shift;

    unless( ref $self ) {
        $self = fields::new( $self );
    }

    return $self;
}

####
# Declare which parameters should be provided for this scaffold.
sub pars {
    my $self = shift;

    return {
        'name' => {
            'index'       => 10,
            'description' => <<DESC
Name of the package
DESC
        },
        'developer' => {
            'index'       => 20,
            'description' => <<DESC
URL of the developer, such as your company URL
DESC
        },
        'url' => {
            'index'       => 30,
            'description' => <<DESC
URL of the package, such as a product information page on your company website
DESC
        },
        'description' => {
            'index'       => 40,
            'description' => <<DESC
One-line description of your package, which will be shown to the user when
they ask pacman about your package (-i flag to pacman)
DESC
        },
        'license' => {
            'index'       => 50,
            'description' => <<DESC
License of your package, such as GPL, Apache, or Proprietary
DESC
        }
    };
}

####
# Do the generation
# $pars: the parameters to use
# $dir: the output directory
sub generate {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    my $packageName = $pars->{name};

    unless( $dir ) {
        $dir = $packageName;
    }
    $self->ensurePackageDirectory( $dir );

    my $pkgbuildContent = $self->pkgbuildContent( $pars, $dir );
    my $manifestContent = $self->manifestContent( $pars, $dir );

    if( $pkgbuildContent ) {
        UBOS::Utils::saveFile( "$dir/PKGBUILD", $pkgbuildContent, 0644 );
    }
    if( $manifestContent ) {
        UBOS::Utils::saveFile( "$dir/ubos-manifest.json", $manifestContent, 0644 );
    }

    UBOS::Utils::mkdir( "$dir/appicons" );
    $self->copyIcons( $pars, "$dir/appicons" );

    my $htAccessTmpl = $self->htAccessTmplContent( $pars, $dir );
    if( $htAccessTmpl ) {
        unless( -d "$dir/tmpl" ) {
            UBOS::Utils::mkdir( "$dir/tmpl" );
        }
        UBOS::Utils::saveFile( "$dir/tmpl/htaccess.tmpl", $htAccessTmpl, 0644 );
    }

    my $gitIgnore = $self->gitIgnoreContent( $pars, $dir );
    if( $gitIgnore ) {
        UBOS::Utils::saveFile( "$dir/.gitignore", $gitIgnore, 0644 );
    }
    return $self;
}

####
# Obtain the content of the PKGBUILD file.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub pkgbuildContent {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    my $ret = $self->pkgbuildContentHeader( $pars, $dir );

    my $vars = $self->pkgbuildContentVars( $pars, $dir );
    if( keys %$vars ) {
        $ret .= join( "\n", map { "$_=" . $vars->{$_}; } sort keys %$vars ) . "\n";
    }

    my $prepareFunction = $self->pkgbuildContentPrepare( $pars, $dir );
    my $buildFunction   = $self->pkgbuildContentBuild(   $pars, $dir );
    my $packageFunction = $self->pkgbuildContentPackage( $pars, $dir );
    my $contentOther    = $self->pkgbuildContentOther(   $pars, $dir );

    if( $prepareFunction ) {
        $prepareFunction = $self->indent( $prepareFunction );
        $ret .= <<END
prepare() {
$prepareFunction}

END
    }
    if( $buildFunction ) {
        $buildFunction = $self->indent( $buildFunction );
        $ret .= <<END
build() {
$buildFunction}

END
    }
    if( $packageFunction ) {
        $packageFunction = $self->indent( $packageFunction );
        $ret .= <<END
package() {
$packageFunction}

END
    }
    if( $contentOther ) {
        $ret .= $contentOther;
    }

    return $ret;
}

####
# Obtain the header of the PKGBUILD file.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub pkgbuildContentHeader {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    my $name = $pars->{name};

    return <<END;
#
# PKGBUILD for package $name, generated by ubos-scaffold.
# For the syntax of this file, please refer to the description on the
# Arch Linux wiki here: https://wiki.archlinux.org/index.php/PKGBUILD
#
END
}

####
# Obtain the bash variables in the PKGBUILD file. This returns a hash,
# so it is easier for subclasses to incrementally modify.
# $pars: the parameters to use
# $dir: the output directory
# return: name-value pairs
sub pkgbuildContentVars {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    my $ret = {
        'developer'  => $pars->{developer},
        'url'        => $pars->{url},
        'maintainer' => $pars->{developer},
        'pkgname'    => '$(basename $(pwd))',
        'pkgver'     => '0.1',
        'pkgrel'     => '1',
        'pkgdesc'    => '"' . $pars->{description} . '"',
        'arch'       => '("any")',
        'license'    => '("' . $pars->{license} . '")',
        'depends'    => <<END,
(
    # Insert your UBOS package dependencies here as a bash array, like this:
    #     'perl-archive-zip' 'ubos-perl-utils'
    # and close with a parenthesis
)
END
        'backup' => <<END,
(
    # List any config files your package uses that should NOT be overridden
    # upon the next package update if the user has modified them.
)
END
        'source' => <<END,
(
    # Insert URLs to the source(s) of your code here, usually one or more tar files
    # or such, like this:
    #     "https://download.nextcloud.com/server/releases/nextcloud-\${pkgver}.tar.bz2"
)
END
        'sha512sums' => <<END,
(
    # List the checksums for one source at a time, same sequence as the in
    # the sources array, like this:
    #     '1c1e59d3733d4c1073c19f54c8eda48f71a7f9e8db74db7ab761fcd950445f7541bce5d9ac800238ab7099ff760cb51bd59b7426020128873fa166870c58f125'
)
END
    };
    return $ret;    
}

####
# Obtain the content of the prepare method in the PKGBUILD file.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub pkgbuildContentPrepare {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    return undef;
}

####
# Obtain the content of the build method in the PKGBUILD file.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub pkgbuildContentBuild {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    return <<END;
# If your package requires compilation, insert your build code here
cd "\${srcdir}/\${pkgname}-\${pkgver}"
echo Building ...
END
}

####
# Obtain the content of the package method in the PKGBUILD file.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub pkgbuildContentPackage {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    return <<END;
# Manifest
install -D -m0644 \${startdir}/ubos-manifest.json \${pkgdir}/ubos/lib/ubos/manifests/\${pkgname}.json

# Icons
install -D -m0644 \${startdir}/appicons/{72x72,144x144}.png -t \${pkgdir}/ubos/http/_appicons/\${pkgname}/

# Data
mkdir -p \${pkgdir}/ubos/lib/\${pkgname}

# Config files
mkdir -p \${pkgdir}/etc/\${pkgname}

# Template files
install -p -m0644 \${startdir}/tmpl/* -t \${pkgdir}/ubos/share/{pkgname}/tmpl/

# Command-line executables
# install your command-line executables here, such as:
# install -D -m0755 \${startdir}/my-script \${pkgdir}/usr/bin/
END
}

####
# Obtain other content that goes into the PKGBUILD file.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub pkgbuildContentOther {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    return undef;
}

####
# Obtain the content of the UBOS manifest.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub manifestContent {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    return undef;
}

####
# Obtain the content of the a .htaccess or Apache config fragment file.
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub htAccessTmplContent {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    return undef;
}

####
# Obtain the content of the .gitignore file
# $pars: the parameters to use
# $dir: the output directory
# return: the content
sub gitIgnoreContent {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    my $name = $pars->{name};

    return <<END;
$name-*any.pkg*
END
}


####
# Default implementation to copy the icons.
# $pars: the parameters to use
# $dir: the output directory
sub copyIcons {
    my $self = shift;
    my $pars = shift;
    my $dir  = shift;

    for my $f ( '72x72.png', '144x144.png' ) {
        UBOS::Utils::myexec( "cp '/usr/share/ubos-scaffold/default-appicons/$f' '$dir'" );
    }
    1;
}

####
# Ensure that this package directory exists and isn't already used
# $dir: the package directory
# return: 0: ok. 1: directory had to be created.
sub ensurePackageDirectory {
    my $self = shift;
    my $dir  = shift;

    my $ret = 0;
    if( -d $dir ) {
        foreach my $f ( qw( PKGBUILD ubos-manifest.json )) {
            if( -e "$dir/$f" ) {
                fatal( "$dir/$f exists: refusing to proceed\n" );
            }
        }
    } elsif( UBOS::Utils::mkdir( $dir )) {
        $ret = 1;
    } else {
        fatal( 'Cannot find or create', $dir );
    }
    return $ret;
}

####
# Indent some text
# $t: text
# $i: how many levels
# return: indented text
sub indent {
    my $self = shift;
    my $t    = shift;
    my $i    = shift || 1;

    my $replace = '    ' x $i;
    $t =~ s!^!$replace!mg;
    return $t;
}

1;

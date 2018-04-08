#!/usr/bin/perl
#
# A dummy scaffold. For testing only.
#
# Copyright (C) 2014 and later, Indie Computing Corp. All rights reserved. License: see package.
#

use strict;
use warnings;

package UBOS::WebAppTest::Scaffolds::Dummy;

use base qw( UBOS::WebAppTest::AbstractRemoteScaffold );
use fields qw( directory name sshPublicKeyFile
               bootMaxSeconds shutdownMaxSeconds
               nspawnLogFile staffDir );

use File::Temp qw( tempdir );
use Socket;
use UBOS::Logging;
use UBOS::Utils;

my $defaultKeysDir    = 'local.ssh';
my $defaultPublicKey  = "$defaultKeysDir/id_rsa.pub";
my $defaultPrivateKey = "$defaultKeysDir/id_rsa";

##
# Instantiate the Scaffold.
# $options: hash of options
sub setup {
    my $self    = shift;
    my $options = shift;

    unless( ref $self ) {
        $self = fields::new( $self );
    }
    $self->SUPER::setup( $options );

    trace( 'Setting up Dummy scaffold with options', sub {
        join( ', ', map { "$_ => " . $options->{$_}} keys %$options )
    } );

    # make sure ip_forwarding is set for the default route upstream
    my $out;
    my $depotIp;
    my $depotNic;
    my $depotNicForwarding=0;
    for( my $i=0 ; $i<5 ; ++$i ) {
        UBOS::Utils::myexec( 'getent ahostsv4 depot.ubos.net', undef, \$out );
        if( $out =~ m!^(\d+\.\d+\.\d+\.\d+)\s+STREAM! ) {
                # 52.23.168.209   STREAM depot.ubos.net
                # 52.23.168.209   DGRAM
                # 52.23.168.209   RAW
            $depotIp = $1;

        } else {
            next;
        }

        UBOS::Utils::myexec( 'ip route get ' . $depotIp, undef, \$out );
        if( $out =~ m!^\d+\.\d+\.\d+\.\d+ via \d+\.\d+\.\d+\.\d+ \S+ (\S+)! ) {
                # 52.23.168.209 via 192.168.138.1 dev enp0s3  src 192.168.138.144
                # cache
            $depotNic = $1;

        } else {
            next;
        }

        UBOS::Utils::myexec( "sudo sysctl net.ipv4.conf.$depotNic.forwarding=1", undef, \$out );
        if( UBOS::Utils::slurpFile( "/proc/sys/net/ipv4/conf/$depotNic/forwarding" ) =~ m!1! ) {
            $depotNicForwarding=1;
            last;
        }

        sleep( 2 );
    }
    if( !defined( $depotIp )) {
        fatal( 'Failed to determine IPv4 address of depot.ubos.net' );
    } elsif( !defined( $depotNic )) {
        fatal( 'Failed to determine NIC of route to depot.ubos.net' );
    } elsif( $depotNicForwarding==0 ) {
        fatal( 'Failed to set IPv4 forwarding on upstream NIC', $depotNic );
    }

    $self->{isOk} = 0; # until we decide otherwise

    my $name;
    if( exists( $options->{name} )) {
        $self->{name} = $options->{name};
        delete $options->{name};
    } else {
        # The name needs to be unique in the first 11 chars because the virtual nic
        # uses it, which has only 14 chars total and starts with ve-
        my $now = UBOS::Utils::time2string( time() );
        $self->{name} = 't-' . substr( $now, length( $now )-9 ) . '-webapptest';
    }

    if( exists( $options->{'shepherd'} )) {
        unless( $options->{'shepherd'} ) {
            fatal( 'Value for shepherd cannot be empty' );
        }
        $self->{sshUser} = $options->{'shepherd'};
        delete $options->{'shepherd'};
    } else {
        $self->{sshUser} = 'shepherd';
    }

    if( exists( $options->{'shepherd-public-key-file'} )) {
        unless( $options->{'shepherd-public-key-file'} ) {
            fatal( 'Empty value for shepherd-public-key-file' );
        }
        unless( -r $options->{'shepherd-public-key-file'} ) {
            fatal( 'Cannot find or read file', $options->{'shepherd-public-key-file'} );
        }
        unless( exists( $options->{'shepherd-private-key-file'} )) {
            fatal( 'If providing shepherd-public-key-file, must also provide value for shepherd-private-key-file' );
        }
        unless( $options->{'shepherd-private-key-file'} ) {
            fatal( 'Empty value for shepherd-private-key-file' );
        }
        unless( -r $options->{'shepherd-private-key-file'} ) {
            fatal( 'Cannot find or read file', $options->{'shepherd-private-key-file'} );
        }

        $self->{sshPublicKeyFile}  = delete $options->{'shepherd-public-key-file'};
        $self->{sshPrivateKeyFile} = delete $options->{'shepherd-private-key-file'};

    } elsif( exists( $options->{'shepherd-private-key-file'} )) {
        fatal( 'If providing shepherd-private-key-file, must also provide value for shepherd-public-key-file' );

    } else {
        # have neither, use defaults
        unless( -d $defaultKeysDir ) {
            unless( UBOS::Utils::mkdir( $defaultKeysDir )) {
                fatal( 'Failed to create directory', $defaultKeysDir );
            }
        }
        if( -e $defaultPublicKey ) {
            if( ! -e $defaultPrivateKey ) {
                fatal( 'Cannot find default public ssh key at', $defaultPublicKey, 'but have default private ssh key' );
            }
            info( 'Reusing default ssh keys for container access in directory', $defaultKeysDir );
        } elsif( -e $defaultPrivateKey ) {
            fatal( 'Cannot find default private ssh key at', $defaultPublicKey, 'but have default public ssh key' );
        } else {
            if( UBOS::Utils::myexec( 'ssh-keygen -q -N "" -f ' . $defaultPrivateKey )) {
                fatal( 'Automatic generation of ssh keypair for webapptest failed' );
            }
            if( ! -e $defaultPublicKey || ! -e $defaultPrivateKey ) {
                fatal( 'Cannot find generated ssh keypair file(s)' );
            }
            info( 'Generated ssh keys for container access in directory', $defaultKeysDir );
        }
        $self->{sshPublicKeyFile}  = $defaultPublicKey;
        $self->{sshPrivateKeyFile} = $defaultPrivateKey;
    }

    trace( 'Creating dummy', $self->{name} );

    unless( exists( $options->{directory} )) {
        fatal( 'No value provided for directory' );
    }
    if( $options->{directory} =~ m!^~([^/]*)(/.*)?$! ) {
        # allow ~/foo and ~bar/foo
        my $user = $1 || getlogin || getpwuid($<);
        my $dir  = $2;
        my $line;
        UBOS::Utils::myexec( "getent passwd $user", undef, \$line );
        my $home = ( split /:/, $line )[5];

        $options->{directory} = $home . $dir;
    }
    unless( -d $options->{directory} ) {
        fatal( 'directory does not exist or cannot be read:', $options->{directory} );
    }

    if( exists( $options->{'boot-max-seconds'} )) {
        $self->{bootMaxSeconds} = $options->{'boot-max-seconds'};
        delete $options->{'boot-max-seconds'};
    } else {
        $self->{bootMaxSeconds} = 240;
    }

    if( exists( $options->{'shutdown-max-seconds'} )) {
        $self->{shutdownMaxSeconds} = $options->{'shutdown-max-seconds'};
        delete $options->{'shutdown-max-seconds'};
    } else {
        $self->{shutdownMaxSeconds} = 120;
    }

    my $bind;
    if( exists( $options->{bind} )) {
        $bind = $options->{bind};
        delete $options->{bind};
    }

    $self->{directory}         = delete $options->{directory};
    my $impersonateDepot       = delete $options->{impersonatedepot};

    if( defined( $options ) && %$options ) {
        fatal( 'Unknown option(s) for Scaffold container:', join( ', ', keys %$options ));
    }

    trace( 'Creating ubos-staff config directory' );

    $self->{staffDir} = tempdir( CLEANUP => 0 ); # need to manually clean up, may contain root-owned files
    chmod 0755, $self->{staffDir}; # So it's consistent with the package
    $self->populateConfigDir( $self->{staffDir} );

    $self->{nspawnLogFile} = File::Temp->new();

    my $cmd = "sudo systemd-nspawn";
    $cmd .= " --boot";
    $cmd .= " --ephemeral";
    $cmd .= " --network-veth";
    $cmd .= " --machine=" . $self->{name};
    $cmd .= " --directory '" . $self->{directory} . "'";
    $cmd .= " --bind '" . $self->{staffDir} . ":/UBOS-STAFF'"; # UBOS staff
    if( $bind ) {
        $cmd .= " --bind '$bind'";
    }
    $cmd .= " --system-call-filter=set_tls"; # Bug in systemd: https://github.com/systemd/systemd/issues/7135
    $cmd .= " > '" . $self->{nspawnLogFile}->filename . "'";
    $cmd .= " 2>&1";
    $cmd .= " &";                                          # run in background; we don't want the login prompt

    info( 'Creating scaffold dummy:', $cmd );

    $self->{isOk} = 1;
    $self->{sshHost} = '1.1.1.1';

    return $self;
}

##
# Teardown this Scaffold.
sub teardown {
    my $self = shift;

    my $containerName = $self->{name};

    info( "Tearing down scaffold dummy: sudo machinectl poweroff '$containerName'" );

    if( -d $self->{staffDir} ) {
        # may contain root-owned files
        UBOS::Utils::myexec( "sudo rm -rf '" . $self->{staffDir} . "'" );
    }

    return 1;
}

##
# Populate a UBOS staff directory
# $dir: name of the directory
sub populateConfigDir {
    my $self = shift;
    my $dir  = shift;

    my $sshPubKey = UBOS::Utils::slurpFile( $self->{sshPublicKeyFile} );
    $sshPubKey =~ s!^\s+!!;
    $sshPubKey =~ s!\s+$!!;

    unless( -d "$dir/shepherd/ssh" ) {
        UBOS::Utils::myexec( "mkdir -p '$dir/shepherd/ssh'" );
    }

    UBOS::Utils::saveFile( "$dir/shepherd/ssh/id_rsa.pub", $sshPubKey );
}

##
# Copy a remote file to the local machine
# $remoteFile: the name of the file on the remote machine
# $localFile: the name of the file on the local machine
sub copyFromTarget {
    my $self       = shift;
    my $remoteFile = shift;
    my $localFile  = shift;

    my $scpCmd = 'scp -q';
    $scpCmd .= ' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error';
            # don't put into known_hosts file, and don't print resulting warnings
    if( $self->{sshPrivateKeyFile} ) {
        $scpCmd .= ' -i ' . $self->{sshPrivateKeyFile};
    }
    $scpCmd .= ' ' . $self->{sshUser} . '@' . $self->{sshHost} . ':' . $remoteFile;
    $scpCmd .= ' ' . $localFile;
    trace( 'scp command:', $scpCmd );

    my $ret = 0; # UBOS::Utils::myexec( $scpCmd );
    return $ret;
}

##
# Copy a local file to the remote machine
# $localFile: the name of the file on the local machine
# $remoteFile: the name of the file on the remote machine
sub copyToTarget {
    my $self       = shift;
    my $localFile  = shift;
    my $remoteFile = shift;

    info( "copyToTarget $localFile $remoteFile" );
    return 0;
    my $scpCmd = 'scp -q';
    $scpCmd .= ' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error';
            # don't put into known_hosts file, and don't print resulting warnings
    if( $self->{sshPrivateKeyFile} ) {
        $scpCmd .= ' -i ' . $self->{sshPrivateKeyFile};
    }
    $scpCmd .= ' ' . $localFile;
    $scpCmd .= ' ' . $self->{sshUser} . '@' . $self->{sshHost} . ':' . $remoteFile;
    trace( 'scp command:', $scpCmd );

    my $ret = 0; # UBOS::Utils::myexec( $scpCmd );
    return $ret;
}

##
# Helper method to invoke a command on the target. This must be overridden by subclasses.
# $cmd: command
# $stdin: content to pipe into stdin
# $stdout: content captured from stdout
# $stderr: content captured from stderr
# return: exit code
sub invokeOnTarget {
    my $self   = shift;
    my $cmd    = shift;
    my $stdin  = shift;
    my $stdout = shift;
    my $stderr = shift;

    if( $self->{verbose} ) {
        if( $stdin ) {
            info( 'Scaffold', $self->name(), "exec: $cmd << INPUT\n$stdin\nINPUT" );
        } else {
            info( 'Scaffold', $self->name(), "exec: $cmd" );
        }
    }

    my $sshCmd = 'ssh';
    $sshCmd .= ' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error';
            # don't put into known_hosts file, and don't print resulting warnings
    $sshCmd .= ' ' . $self->{sshUser} . '@' . $self->{sshHost};
    if( $self->{sshPrivateKeyFile} ) {
        $sshCmd .= ' -i ' . $self->{sshPrivateKeyFile};
    }
    $sshCmd .= " '$cmd'";

    my $ret = 0; #  UBOS::Utils::myexec( $sshCmd, $stdin, $stdout, $stderr );

    if( $ret == 0 && $stderr ) {
        if( $$stderr =~ m!^(FATAL|ERROR|WARNING):! ) {
            # Guess the command was wrong, it didn't return an error code
            $ret = -999;
        } else {
            # If there are no errors, zap the log output
            $$stderr = '';
        }
    }
    return $ret;
}

##
# Return help text.
# return: help text
sub help {
    return <<TXT;
A dummy scaffold, for testing webapptest only.
Options:
    directory                 (required) -- directory containing UBOS that becomes the root directory for the container
    name                      (optional) -- name of the container to create
    shepherd                  (optional) -- name of the user on the virtual machine that can execute ubos-admin over ssh
    shepherd-public-key-file  (required) -- name of the file that contains the public key for ubos-admin ssh access
    shepherd-private-key-file (required) -- name of the file that contains the private key for ubos-admin ssh access
    boot-max-seconds          (optional) -- the maximum number of seconds to wait for the boot to complete
    keys-max-seconds          (optional) -- the maximum number of seconds to wait until keys have been generated
    shutdown-max-seconds      (optional) -- the maximum number of seconds to wait until shutdown is complete
TXT
}

1;

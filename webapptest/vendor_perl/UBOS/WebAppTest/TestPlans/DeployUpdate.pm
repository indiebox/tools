#!/usr/bin/perl
#
# Deploys the app, updates the app and only tests the virgin state.
#
# Copyright (C) 2014 and later, Indie Computing Corp. All rights reserved. License: see package.
#

use strict;
use warnings;

package UBOS::WebAppTest::TestPlans::DeployUpdate;

use base qw( UBOS::WebAppTest::AbstractSingleSiteTestPlan );
use fields qw( upgradeToChannel switchChannelCommand maxTransitions );

use UBOS::Logging;
use UBOS::Utils;
use UBOS::WebAppTest::TestContext;
use UBOS::WebAppTest::TestingUtils;

##
# Instantiate the TestPlan.
# $test: the test to run
# $options: options for the test plan
# $tlsData: if given, the TLS section of the Site JSON to use
sub new {
    my $self    = shift;
    my $test    = shift;
    my $options = shift;
    my $tlsData = shift;

    unless( ref $self ) {
        $self = fields::new( $self );
    }
    $self = $self->SUPER::new( $test, $options, $tlsData );

    if( exists( $options->{'upgrade-to-channel'} )) {
        $self->{upgradeToChannel} = $options->{'upgrade-to-channel'};
        delete $options->{'upgrade-to-channel'};
    }
    if( exists( $options->{'switch-channel-command'} )) {
        $self->{switchChannelCommand} = $options->{'switch-channel-command'};
        delete $options->{'switch-channel-command'};
    }
    if( exists( $options->{'max-transitions'} )) {
        $self->{maxTransitions} = $options->{'max-transitions'};
        delete $options->{'max-transitions'};
    } else {
        $self->{maxTransitions} = 1;
    }

    if( defined( $options ) && %$options ) {
        fatal( 'Unknown option(s) for TestPlan DeployUpdate:', join( ', ', keys %$options ));
    }

    return $self;
}

##
# Run this TestPlan
# $scaffold: the Scaffold to use
# $interactive: if 1, ask the user what to do after each error
# $verbose: verbosity level from 0 (not verbose) upwards
sub run {
    my $self        = shift;
    my $scaffold    = shift;
    my $interactive = shift;
    my $verbose     = shift;

    info( 'Running testplan deploy-update' );

    my $siteJson = $self->getSiteJson();

    my $ret = 1;
    my $success;
    my $repeat;
    my $abort;
    my $quit;

    do {
        $success = $scaffold->deploy( $siteJson );

        ( $repeat, $abort, $quit ) = UBOS::WebAppTest::TestingUtils::askUser( 'Performed deployment', $interactive, $success, $ret );

    } while( $repeat );
    $ret &= $success;

    # do not check pre-upgrade states, the tests and/or paths may be all different

    if( !$abort && !$quit ) {
        my $c = new UBOS::WebAppTest::TestContext( $scaffold, $self, $verbose );

        my $currentState    = $self->getTest()->getVirginStateTest();
        my $transitionCount = 0;
        while( $transitionCount < $self->{maxTransitions} ) {
            ++$transitionCount;

            my( $transition, $nextState ) = $self->getTest()->getTransitionFrom( $currentState );
            unless( $transition ) {
                last;
            }

            info( 'Taking StateTransition', $transition->getName() );

            do {
                $success = $transition->execute( $c );

                ( $repeat, $abort, $quit ) = UBOS::WebAppTest::TestingUtils::askUser( 'Performed StateTransition ' . $transition->getName(), $interactive, $success, $ret );

            } while( $repeat );
            $ret &= $success;

            if( $abort || $quit ) {
                last;
            }

            $currentState = $nextState;
        }

        # now upgrade

        if( !$abort && !$quit ) {
            do {
                do {
                    if( $self->{upgradeToChannel} ) {
                        info( 'Switching to channel', $self->{upgradeToChannel}, 'and updating' );
                        $success = $scaffold->switchChannelUpdate( $self->{upgradeToChannel}, $verbose, $self->{switchChannelCommand} );
                    } else {
                        info( 'Updating' );
                        $success = $scaffold->update();
                    }

                   ( $repeat, $abort, $quit ) = UBOS::WebAppTest::TestingUtils::askUser( 'Performed update', $interactive, $success, $ret );
                } while( $repeat );

                if( !$abort && !$quit ) { # apparently, do-while is "not a loop" in Perl, so I can't do "last" here.

                    info( 'Checking StateCheck', $currentState->getName() );

                    $success = $currentState->check( $c );

                    ( $repeat, $abort, $quit ) = UBOS::WebAppTest::TestingUtils::askUser( 'Performed StateCheck ' . $currentState->getName(), $interactive, $success, $ret );
                }

            } while( $repeat );
            $ret &= $success;
        }
        $c->destroy();
    }

    unless( $abort ) {
        $scaffold->undeploy( $siteJson );
    }
    
    info( 'End running TestPlan DeployUpdate' );

    return $ret;
}

##
# Return help text.
# return: help text
sub help {
    return 'Tests whether the application can be installed and updated.';
}

##
# Return allowed arguments for this command.
# return: allowed arguments, as string
sub helpArguments {
    return undef;
}

1;

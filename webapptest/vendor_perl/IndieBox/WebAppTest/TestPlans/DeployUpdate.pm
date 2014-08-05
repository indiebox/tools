#!/usr/bin/perl
#
# Deploys the app, updates the app and only tests the virgin state.
#
# This file is part of webapptest.
# (C) 2012-2014 Indie Computing Corp.
#
# webapptest is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# webapptest is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with webapptest.  If not, see <http://www.gnu.org/licenses/>.
#

use strict;
use warnings;

package IndieBox::WebAppTest::TestPlans::DeployUpdate;

use base qw( IndieBox::WebAppTest::AbstractSingleSiteTestPlan );
use fields;
use IndieBox::Logging;
use IndieBox::WebAppTest::TestContext;
use IndieBox::Utils;

##
# Instantiate the TestPlan.
sub new {
    my $self = shift;

    unless( ref $self ) {
        $self = fields::new( $self );
    }
    $self = $self->SUPER::new();

    return $self;
}

##
# Run this TestPlan
# $test: the AppTest to run
# $scaffold: the Scaffold to use
# $interactive: if 1, ask the user what to do after each error
sub run {
    my $self        = shift;
    my $test        = shift;
    my $scaffold    = shift;
    my $interactive = shift;

    info( 'Running TestPlan DeployUpdate' );

    my( $siteJson, $appConfigJson ) = $test->getSiteAndAppConfigJson();

    my $ret = 1;
    my $success;
    my $repeat;
    my $abort;
    my $quit;

    do {
        $success = $scaffold->deploy( $siteJson );

        ( $repeat, $abort, $quit ) = $self->askUser( 'Performed deployment', $interactive, $success, $ret );

    } while( $repeat );
    $ret &= $success;

    my $c = new IndieBox::WebAppTest::TestContext( $siteJson, $appConfigJson, $scaffold, $test, $self, $scaffold->getTargetIp() );
    if( !$abort && !$quit ) {
        my $currentState = $test->getVirginStateTest();

        info( 'Checking StateCheck', $currentState->getName() );

        do {
            $success = $currentState->check( $c );

            ( $repeat, $abort, $quit ) = $self->askUser( 'Performed StateCheck ' . $currentState->getName(), $interactive, $success, $ret );

        } while( $repeat );
        $ret &= $success;
    }
    if( !$abort && !$quit ) {
        my $currentState = $test->getVirginStateTest();

        do {
            do { 
                info( 'Updating' );

                $success = $scaffold->update();

               ( $repeat, $abort, $quit ) = $self->askUser( 'Performed update', $interactive, $success, $ret );
            } while( $repeat );

            if( !$abort && !$quit ) { # apparently, do-while is "not a loop" in Perl, so I can't do "last" here.
                
                info( 'Checking StateCheck', $currentState->getName() );

                $success = $currentState->check( $c );

                ( $repeat, $abort, $quit ) = $self->askUser( 'Performed StateCheck ' . $currentState->getName(), $interactive, $success, $ret );
            }
            
        } while( $repeat );
        $ret &= $success;
    }
    
    $c->destroy();

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

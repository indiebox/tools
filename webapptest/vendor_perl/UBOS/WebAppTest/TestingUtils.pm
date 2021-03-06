#!/usr/bin/perl
#
# Collection of utility methods for web app testing.
#
# Copyright (C) 2014 and later, Indie Computing Corp. All rights reserved. License: see package.
#

use strict;
use warnings;

package UBOS::WebAppTest::TestingUtils;

use Cwd;
use UBOS::Logging;
use UBOS::Utils;

##
# Find all AppTests in a directory.
# $dir: directory to look in
# return: hash of file name to AppTest object
sub findAppTestsInDirectory {
    my $dir = shift;

    unless( -d $dir ) {
        fatal( 'Not a directory or not readable:', $dir );
    }

    my $appTestCandidates = UBOS::Utils::readFilesInDirectory( $dir, '.*Test.*\.pm$' );
    my $appTests = {};

    foreach my $fileName ( keys %$appTestCandidates ) {
        my $content = $appTestCandidates->{$fileName};

        my $appTest = eval $content;

        if( defined( $appTest ) && $appTest->isa( 'UBOS::WebAppTest' )) {
            $appTests->{$fileName} = $appTest;

        } elsif( $@ ) {
            error( 'Failed to parse', $fileName, ':', $@ );
            
        } else {
            info( 'Skipping', $fileName, '-- not an AppTest' );
        }
    }
    return $appTests;
}

##
# Find available commands.
# return: hash of command name to full package name
sub findCommands {
    my $ret = UBOS::Utils::findPerlShortModuleNamesInPackage( 'UBOS::WebAppTest::Commands' );

    return $ret;
}

##
# Find available test plans
# return: hash of test plan name to full package name
sub findTestPlans {
    my $ret = UBOS::Utils::findPerlShortModuleNamesInPackage( 'UBOS::WebAppTest::TestPlans' );

    return $ret;
}

##
# Find a named test plan
# $name: name of the test plan
# return: test plan template, or undef
sub findTestPlan {
    my $name = shift;

    my $plans = findTestPlans();
    my $ret   = $plans->{$name};

    return $ret;
}

##
# Find available test scaffolds.
# return: hash of scaffold name to full package name
sub findScaffolds {
    my $ret = UBOS::Utils::findPerlShortModuleNamesInPackage( 'UBOS::WebAppTest::Scaffolds' );
    return $ret;
}

##
# Find a named scaffold
# $name: name of the scaffold
# return: scaffold package, or undef
sub findScaffold {
    my $name = shift;

    my $scaffolds = findScaffolds();
    my $ret       = $scaffolds->{$name};

    return $ret;
}

##
# Find a named AppTest in a directory.
# $dir: directory to look in
# $name: name of the test
# return: the AppTest object, or undef
sub findAppTestInDirectory {
    my $dir  = shift;
    my $name = shift;

    my $fileName;
    if( $name =~ m!^/! ) {
        $fileName = $name;
    } else {
        $fileName = getcwd() . "/$name";
    }

    if( !-r $fileName && $fileName !~ m!\.pm$! ) {
        $fileName = "$fileName.pm";
    }
    if( -r $fileName && -f $fileName ) {
        my $content = UBOS::Utils::slurpFile( $fileName );
        
        my $appTest = eval $content;

        if( defined( $appTest ) && $appTest->isa( 'UBOS::WebAppTest' )) {
            return $appTest;

        } elsif( $@ ) {
            error( 'Failed to parse', $fileName, ':', $@ );
            
        } else {
            error( 'Not a UBOS::WebAppTest:', $fileName );
        }
    }        
    return undef;
}

##
# If interactive, ask the user what to do next. If non-interactive, proceed.
# $question: the question to ask
# $interactive: if false, continue and do not ask
# $successOfLastStep: did the most recent step succeed?
# $successOfPlanSoFar: if true, all steps have been successful so far
sub askUser {
    my $question           = shift;
    my $interactive        = shift;
    my $successOfLastStep  = shift;
    my $successOfPlanSoFar = shift;

    my $repeat = 0;
    my $abort  = 0;   
    my $quit   = !$successOfLastStep;

    if( $interactive ) {
        my $fullQuestion;
        if( $question ) {
            $fullQuestion = $question . ' (' . ( $successOfLastStep ? 'success' : 'failure' ) . ').';
        } else {
            $fullQuestion = 'Last step ' . ( $successOfLastStep ? 'succeeded' : 'failed' ) . '.';
        }
        $fullQuestion .= " C(ontinue)/R(epeat)/A(bort)/Q(uit)? ";
        
        while( 1 ) {
            print STDERR $fullQuestion;

            my $userinput = <STDIN>;
            if( $userinput =~ /^\s*c\s*$/i ) {
                $repeat = 0;
                $abort  = 0;
                $quit   = 0;
                last;
            }
            if( $userinput =~ /^\s*r\s*$/i ) {
                $repeat = 1;
                $abort  = 0;
                $quit   = 0;
                last;
            }
            if( $userinput =~ /^\s*a\s*$/i ) {
                $repeat = 0;
                $abort  = 1;
                $quit   = 0;
                last;
            }
            if( $userinput =~ /^\s*q\s*$/i ) {
                $repeat = 0;
                $abort  = 0;
                $quit   = 1;
                last;
            }
        }
    }

    return( $repeat, $abort, $quit );
}

1;

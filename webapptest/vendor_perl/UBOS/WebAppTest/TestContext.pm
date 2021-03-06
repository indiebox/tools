#!/usr/bin/perl
#
# Passed to an AppTest. Holds the run-time information the test needs to function.
#
# Copyright (C) 2014 and later, Indie Computing Corp. All rights reserved. License: see package.
#

use strict;
use warnings;

package UBOS::WebAppTest::TestContext;

use fields qw( scaffold testPlan ip verbose curl cookieFile errors );

use Fcntl;
use UBOS::Logging;
use UBOS::Utils;
use UBOS::WebAppTest::TestingUtils;

my $maxWaitTillReady = 60; # Number of seconds to wait until 503 goes away

#
# This file is organized as follows:
# (1) Constructor
# (2) General methods
# (3) HTTP testing methods
# (4) File testing methods
# (5) Utility methods
# Sorry, it's long, but that makes the API a lot easier for the test developer

##### (1) Constructor #####

##
# Instantiate the TextContext.
# $scaffold: the scaffold used for the test
# $testPlan: the TestPlan being execited
# $ip: the IP address at which the application being tested can be accessed
# $verbose: verbosity level from 0 (not verbose) upwards
sub new {
    my $self          = shift;
    my $scaffold      = shift;
    my $testPlan      = shift;
    my $verbose       = shift;

    unless( ref $self ) {
        $self = fields::new( $self );
    }

    $self->{scaffold}      = $scaffold;
    $self->{testPlan}      = $testPlan;
    $self->{ip}            = $scaffold->getTargetIp();
    $self->{verbose}       = $verbose;
    $self->{errors}        = [];

    $self->clearHttpSession();

    return $self;
}

##### (2) General methods #####

##
# Determine the test being run.
# return: the test
sub getTest {
    my $self = shift;

    return $self->{testPlan}->getTest();
}

##
# Determine the scaffold being used.
# return: the Scaffold
sub getScaffold {
    my $self = shift;

    return $self->{scaffold};
}

##
# Determine the test plan being run.
# return: the test plan
sub getTestPlan {
    my $self = shift;

    return $self->{testPlan};
}

##
# Determine the protocol of the application being tested
# return: http, or https
sub protocol {
    my $self = shift;

    return $self->{testPlan}->protocol();
}

##
# Determine the hostname of the application being tested
# return: hostname
sub hostname {
    my $self = shift;

    return $self->{testPlan}->hostname();
}

##
# Determine a valid virtual hostname for the application being tested.
# return: hostname, or if hostname is '*', the IP address
sub hostnameOrIp {
    my $self = shift;

    my $hostname = $self->hostname();
    if( $hostname eq '*' ) {
        $hostname = $self->{ip};
    }
    return $hostname;
}

##
# Determine the context path of the application being tested
# return: context, e.g. /foo
sub context {
    my $self = shift;

    return $self->{testPlan}->context();
}

##
# Determine the full context path of the application being tested
# return: full context, e.g. http://example.com/foo
sub fullContext {
    my $self = shift;

    my $url = $self->protocol() . '://' . $self->hostnameOrIp() . $self->context();
    return $url;
}

##
# Determine the apache context directory of the application being tested.
sub apache2ContextDir {
    my $self = shift;

    return '/ubos/http/sites/' . $self->{testPlan}->siteId() . $self->context();
}

##
# Clear all HTTP session information.
sub clearHttpSession {
    my $self = shift;

    my $hostname   = $self->hostname;
    my $ip         = $self->{ip};
    my $cookieFile = File::Temp->new();

    $self->{cookieFile} = $cookieFile->filename;

    $self->{curl} = "curl -s -v" # -v to get HTTP headers
                  . " --cookie-jar '$cookieFile' -b '$cookieFile'"
                  . " --insecure"
                  . ' -A "Mozilla/5.0 (X11; Linux x86_64; rv:36.0) Gecko/20100101 Firefox/36.0"';
                  # some apps don't like to return content to curl; pretend to be Firefox
    unless( $hostname eq '*' ) {
        $self->{curl} .= " --resolve '$hostname:80:$ip'";
        $self->{curl} .= " --resolve '$hostname:443:$ip'";
    }
}

##### (3) HTTP testing methods #####

##
# Perform an HTTP GET request. If the URL does not contain a protocol and
# hostname but starts with a slash, "http://hostname" with the hostname
# of the site being tested is prepended.
# $url: URL to access
# return: hash containing content and headers of the HTTP response
sub absGet {
    my $self = shift;
    my $url  = shift;

    if( $url !~ m!^[a-z]+://! ) {
        if( $url !~ m!^/! ) {
            return {
                'error' => $self->myerror( 'Cannot access URL without protocol or leading slash:', $url )
            };
        }
        $url = $self->protocol() . '://' . $self->hostnameOrIp() . $url;
    }

    trace( 'Accessing url', $url );

    my $cmd = $self->{curl};
    $cmd .= " '$url'";

    my $stdout;
    my $stderr;
    my $ret = {};

    if( UBOS::Utils::myexec( $cmd, undef, \$stdout, \$stderr )) {
        $ret->{error} = $self->myerror( 'HTTP request failed:', $stderr );
    }
    $ret->{content} = $stdout;
    $ret->{headers} = $stderr;
    $ret->{url}     = $url;

    return $ret;
}

##
# Perform an HTTP GET request on the application being tested, appending to the context URL.
# $relativeUrl: appended to the application's context URL
# return: hash containing content and headers of the HTTP response
sub get {
    my $self        = shift;
    my $relativeUrl = shift;

    return $self->absGet( $self->context() . $relativeUrl );
}

##
# Perform an HTTP POST request. If the URL does not contain a protocol and
# hostname but starts with a slash, "http://hostname" with the hostname
# of the site being tested is prepended.
# $url: URL to access
# $postPars: hash of posted parameters
# return: hash containing content and headers of the HTTP response
sub absPost {
    my $self     = shift;
    my $url      = shift;
    my $postPars = shift;

    if( $url !~ m!^[a-z]+://! ) {
        if( $url !~ m!^/! ) {
            $self->myerror( 'Cannot access URL without protocol or leading slash:', $url );
            return {};
        }
        $url = $self->protocol() . '://' . $self->hostnameOrIp() . $url;
    }

    trace( 'Posting to url', $url );

    my $postData = join(
            '&',
            map { UBOS::Utils::uri_escape( $_ ) . '=' . UBOS::Utils::uri_escape( $postPars->{$_} ) } keys %$postPars );

    my $cmd = $self->{curl};
    $cmd .= " -d '$postData'";
    $cmd .= " '$url'";

    my $stdout;
    my $stderr;
    my $ret = {};

    if( UBOS::Utils::myexec( $cmd, undef, \$stdout, \$stderr )) {
        $ret->{error} = $self->myerror( 'HTTP request failed:', $stderr );
    }
    $ret->{content}     = $stdout;
    $ret->{headers}     = $stderr;
    $ret->{url}         = $url;
    $ret->{postpars}    = $postPars;
    $ret->{postcontent} = $postData;

    return $ret;
}

##
# Perform an HTTP POST request on the application being tested, appending to the context URL,
# with the provided payload.
# $relativeUrl: appended to the application's context URL
# $payload: hash of posted parameters
# return: hash containing content and headers of the HTTP response
sub post {
    my $self        = shift;
    my $relativeUrl = shift;
    my $postData    = shift;

    return $self->absPost( $self->context() . $relativeUrl, $postData );
}

##
# Test that an HTTP GET on a relative URL returns certain content.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $content: the content to look for in the response
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustBe {
    my $self        = shift;
    my $relativeUrl = shift;
    my $content     = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustBe( $response, $content, $errorMsg );

    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL returns content that is not
# certain content.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $content: the content to look for in the response
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustNotBe {
    my $self        = shift;
    my $relativeUrl = shift;
    my $content     = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustNotNe( $response, $content, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL returns a page that contains certain content.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $content: the content to look for in the response
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustContain {
    my $self        = shift;
    my $relativeUrl = shift;
    my $content     = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustContain( $response, $content, $errorMsg );

    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL returns a page that does not
# contain certain content.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $content: the content to look for in the response
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustNotContain {
    my $self        = shift;
    my $relativeUrl = shift;
    my $content     = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustNotContain( $response, $content, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL returns a page that matches a regular expression.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $regex: the regex for the content to look for in the response
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustMatch {
    my $self        = shift;
    my $relativeUrl = shift;
    my $regex       = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustMatch( $response, $regex, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL returns a page that does not
# match a regular expression.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $regex: the regex for the content to look for in the response
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustNotMatch {
    my $self        = shift;
    my $relativeUrl = shift;
    my $regex       = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustNotMatch( $response, $regex, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL returns a page that has a particular length.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $length: length in bytes
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustHaveLength {
    my $self        = shift;
    my $relativeUrl = shift;
    my $length      = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustHaveLength( $response, $length, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL returns a page that does not
# have a particular length
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $length: length in bytes
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustNotHaveLength {
    my $self        = shift;
    my $relativeUrl = shift;
    my $length      = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustNotHaveLength( $response, $length, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL redirects to a certain other URL.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $target: the destination URL
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustRedirect {
    my $self        = shift;
    my $relativeUrl = shift;
    my $target      = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustRedirect( $response, $target, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Test that an HTTP GET on a relative URL does not redirect to a certain
# other URL.
# Convenience method to make tests more concise.
# $relativeUrl: appended to the application's context URL
# $target: the destination URL
# $status: optional HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustNotRedirect {
    my $self        = shift;
    my $relativeUrl = shift;
    my $target      = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustNotRedirect( $response, $target, $errorMsg );
    if( defined( $status )) {
        my $tmp = $self->mustNotStatus( $response, $status, $errorMsg );
        if( defined( $tmp->{error} )) {
            appendError( $ret, $tmp->{error} );
        }
    }
    return $ret;
}

##
# Look for a certain status code in a response.
# $response: the response
# $status: HTTP status to look for
# $errorMsg: if the test fails, report this error message
sub getMustStatus {
    my $self        = shift;
    my $relativeUrl = shift;
    my $status      = shift;
    my $errorMsg    = shift;

    my $response = $self->get( $relativeUrl );
    my $ret      = $self->mustStatus( $response, $status, $errorMsg );

    return $ret;
}

##
# Look for certain content in a response.
# $response: the response
# $content: the content to look for in the response
# $errorMsg: if the test fails, report this error message
sub mustBe {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->is( $response, $content )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content is not', $content );
    }
    return \%ret;
}

##
# Check the content of a response for inequality.
# $response: the response
# $content: the content to look for in the response
sub mustNotBe {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->NotIs( $response, $content )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content is', $content );
    }
    return \%ret;
}

##
# Look for certain content in a response.
# $response: the response
# $content: the content to look for in the response
# $errorMsg: if the test fails, report this error message
sub mustContain {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->contains( $response, $content )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content does not contain', $content );
    }
    return \%ret;
}

##
# Look for the lack of a certain content in a response.
# $response: the response
# $content: the content to look for in the response
# $errorMsg: if the test fails, report this error message
sub mustNotContain {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->notContains( $response, $content )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content contains', $content );
    }
    return \%ret;
}

##
# Look for a regular expression match on the content in a response
# $response: the response
# $regex: the regex for the content to look for in the response
# $errorMsg: if the test fails, report this error message
sub mustMatch {
    my $self     = shift;
    my $response = shift;
    my $regex    = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->matches( $response, $regex )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content does not match regex', $regex );
    }
    return \%ret;
}

##
# Look for a regular expression non-match on the content in a response
# $response: the response
# $regex: the regex for the content to look for in the response
# $errorMsg: if the test fails, report this error message
sub mustNotMatch {
    my $self     = shift;
    my $response = shift;
    my $regex    = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->notMatches( $response, $regex )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content does not match regex', $regex );
    }
    return \%ret;
}

##
# Test that the content in a response has a particular length
# $response: the response
# $length: length in bytes
# $errorMsg: if the test fails, report this error message
sub mustHaveLength {
    my $self     = shift;
    my $response = shift;
    my $length   = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    my $responseLength = length( $response->{content} );
    unless( $length == $responseLength ) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content has wrong length:', $responseLength, 'vs', $length );
    }
    return \%ret;
}

##
# Test that the content in a response does not have a particular length
# $response: the response
# $length: length in bytes
# $errorMsg: if the test fails, report this error message
sub mustNotHaveLengthMatch {
    my $self     = shift;
    my $response = shift;
    my $length   = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    my $responseLength = length( $response->{content} );
    if( $length == $responseLength ) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response content has disallowed length:', $length );
    }
    return \%ret;
}

##
# Look for a redirect to a certain URL in the response
# $response: the response
# $target: the redirect target
# $errorMsg: if the test fails, report this error message
sub mustRedirect {
    my $self     = shift;
    my $response = shift;
    my $target   = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->redirects( $response, $target )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response is not redirecting to', $target );
    }
    return \%ret;
}

##
# Look for the lack of a redirect to a certain URL in the response
# $response: the response
# $target: the redirect target
# $errorMsg: if the test fails, report this error message
sub mustNotRedirect {
    my $self     = shift;
    my $response = shift;
    my $target   = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->notRedirects( $response, $target )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response is redirecting to', $target );
    }
    return \%ret;
}

##
# Look for an HTTP status in the response
# $response: the response
# $status: the HTTP status
# $errorMsg: if the test fails, report this error message
sub mustStatus {
    my $self     = shift;
    my $response = shift;
    my $status   = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->status( $response, $status )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response does not have HTTP status', $status );
    }
    return \%ret;
}

##
# Look for an HTTP status other than the provided one in the response
# $response: the response
# $status: the HTTP status
# $errorMsg: if the test fails, report this error message
sub mustNotStatus {
    my $self     = shift;
    my $response = shift;
    my $status   = shift;
    my $errorMsg = shift;

    my %ret = %$response; # make copy
    unless( $self->notStatus( $response, $status )) {
        debugResponse( $response );
        $ret{error} = $self->myerror( $errorMsg, 'Response has HTTP status',  $status );
    }
    return \%ret;
}

##
# Check the content of a response for equality.
# $response: the response
# $content: the content to look for in the response
sub is {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;

    if( $response->{content} ne $content ) {
        return 0;
    }
    return 1;
}

##
# Check the content of a response for inequality.
# $response: the response
# $content: the content to look for in the response
sub notIs {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;

    if( $response->{content} eq $content ) {
        return 0;
    }
    return 1;
}

##
# Look for certain content in a response.
# $response: the response
# $content: the content to look for in the response
sub contains {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;

    if( $response->{content} !~ m!\Q$content\E! ) {
        return 0;
    }
    return 1;
}

##
# Look for the lack of a certain content in a response.
# $response: the response
# $content: the content to look for in the response
sub notContains {
    my $self     = shift;
    my $response = shift;
    my $content  = shift;

    if( $response->{content} =~ m!\Q$content\E! ) {
        return 0;
    }
    return 1;
}

##
# Look for a regular expression match on the content in a response
# $response: the response
# $regex: the regex for the content to look for in the response
sub matches {
    my $self     = shift;
    my $response = shift;
    my $regex    = shift;

    if( $response->{content} !~ m!$regex! ) {
        return 0;
    }
    return 1;
}

##
# Look for a regular expression non-match on the content in a response
# $response: the response
# $regex: the regex for the content to look for in the response
sub notMatches {
    my $self     = shift;
    my $response = shift;
    my $regex    = shift;

    if( $response->{content} =~ m!$regex! ) {
        return 0;
    }
    return 1;
}

##
# Look for a redirect to a certain URL in the response
# $response: the response
# $target: the redirect target
sub redirects {
    my $self     = shift;
    my $response = shift;
    my $target   = shift;

    if( $target !~ m!^https?://! ) {
        if( $target !~ m!^/! ) {
            $self->myerror( 'Cannot look for target URL without protocol or leading slash', $target );
            return 0;
        }
        $target = $self->fullContext() . $target;
    }

    if( $response->{headers} !~ m!^< Location: \Q$target\E\r?$!m ) {
        return 0;
    }
    return 1;
}

##
# Look for the lack of a redirect to a certain URL in the response
# $response: the response
# $target: the redirect target
sub notRedirects {
    my $self     = shift;
    my $response = shift;
    my $target   = shift;

    if( $target !~ m!^https?://! ) {
        if( $target !~ m!^/! ) {
            $self->myerror( 'Cannot look for target URL without protocol or leading slash', $target );
            return 0;
        }
        $target = $self->fullContext() . $target;
    }

    if( $response->{headers} =~ m!^< Location: \Q$target\E\r?$!m ) {
        return 0;
    }
    return 1;
}

##
# Look for an HTTP status in the response
# $response: the response
# $status: the HTTP status
sub status {
    my $self     = shift;
    my $response = shift;
    my $status   = shift;

    if( $response->{headers} !~ m!HTTP/1\.[01] $status! ) {
        return 0;
    }
    return 1;
}

##
# Look for an HTTP status other than the provided one in the response
# $response: the response
# $status: the HTTP status
sub notStatus {
    my $self     = shift;
    my $response = shift;
    my $status   = shift;

    if( $response->{headers} =~ m!HTTP/1\.1 $status! ) {
        return 0;
    }
    return 1;
}

##
# Wait for an HTTP status other than 503 -- service unavailable
# $url: URL to access
# return: 1 if successful
sub absWaitForReady {
    my $self = shift;
    my $url  = shift;

    my $until = time() + $maxWaitTillReady;
    trace( 'Waiting until ready: ', $maxWaitTillReady, 'sec' );

    while( 1 ) {
        my $response = $self->get( $url );
        my $delta = $until - time();

        if( !$self->status( $response, '503' )) {
            trace( 'Done waiting at:', $delta, 'sec' );
            return 1;
        }

        if( $delta < 0 ) {
            trace( 'Returning at: ', $delta, 'sec' );
            return 0;
        }
        trace( 'Still 503, continuing to wait: ', $delta, 'sec' );
        sleep 5;
    }
}

##
# Wait for an HTTP status other than 503 -- service unavailable
# $relativeUrl: appended to the application's context URL
# return: 1 if successful
sub waitForReady {
    my $self        = shift;
    my $relativeUrl = shift;

    return $self->absWaitForReady( $self->context() . $relativeUrl );
}

##### (4) File testing methods #####

##
# Test that a file exists and has certain content and properties
# $fileName: name of the file
# $fileUname: name of the file's owner, or undef if not to be checked
# $fileGname: name of the file's group, or undef if not to be checked
# $fileMode: number (per chmod) for file permissions, or undef if not the be checked
# $testMethod: a method to invoke which will return 1 (ok) or 0 (fail), or undef
#              if not to be checked. Parameters: 1: this TestContext, 2: fileName
sub checkFile {
    my $self       = shift;
    my $fileName   = shift;
    my $fileUname  = shift;
    my $fileGname  = shift;
    my $fileMode   = shift;
    my $testMethod = shift;

    my( $uname, $gname, $mode, $localContent ) = $self->{scaffold}->getFileInfo( $fileName, defined( $testMethod ));
    unless( defined( $uname )) {
        $self->myerror( 'File does not exist, or error when accessing it:', $fileName );
        return 0;
    }

    my $ret = 1;

    unless( Fcntl::S_ISREG( $mode )) {
        $self->myerror( 'Not a regular file:', $fileName );
        $ret = 0;
    }

    if( defined( $fileMode )) {
        my $realFileMode = ( $fileMode =~ m!^0! ) ? oct( $fileMode ) : $fileMode;
        my $realMode     = $mode & 07777; # ignore special file bits
        if( $realFileMode != $realMode ) {
            $self->myerror( 'File', $fileName, 'has wrong permissions:', sprintf( '0%o vs 0%o', $realFileMode, $realMode ));
            $ret = 0;
        }
    }
    if( defined( $fileUname )) {
        if( $fileUname ne $uname ) {
            $self->myerror( 'File', $fileName, 'has wrong owner:', $fileUname, 'vs.', $uname );
            $ret = 0;
        }
    }
    if( defined( $fileGname )) {
        if( $fileGname ne $gname ) {
            $self->myerror( 'File', $fileName, 'has wrong group:', $fileGname, 'vs.', $gname );
            $ret = 0;
        }
    }
    if( defined( $testMethod )) {
        $ret &= $testMethod->( $self, $localContent );
    }

    return $ret;
}

##
# Test that a directory exists and has certain content and properties
# $dirName: name of the directory
# $dirUname: name of the directory's owner, or undef if not to be checked
# $dirGname: name of the directory's group, or undef if not to be checked
# $dirMode: number (per chmod) for directory permissions, or undef if not the be checked
sub checkDir {
    my $self      = shift;
    my $dirName   = shift;
    my $dirUname  = shift;
    my $dirGname  = shift;
    my $dirMode   = shift;

    my( $uname, $gname, $mode ) = $self->{scaffold}->getFileInfo( $dirName );
    unless( defined( $uname )) {
        $self->myerror( 'Directory does not exist:', $dirName );
        return 0;
    }
    my $ret = 1;

    unless( Fcntl::S_ISDIR( $mode )) {
        $self->myerror( 'Not a directory:', $dirName );
        $ret = 0;
    }

    if( defined( $dirMode )) {
        my $realDirMode = ( $dirMode =~ m!^0! ) ? oct( $dirMode ) : $dirMode;
        my $realMode    = $mode & 07777; # ignore special file bits
        if( $realDirMode != $realMode ) {
            $self->myerror( 'Directory', $dirName, 'has wrong permissions:', sprintf( '0%o vs 0%o', $realDirMode, $realMode ));
            $ret = 0;
        }
    }
    if( defined( $dirUname )) {
        if( $dirUname ne $uname ) {
            $self->myerror( 'Directory', $dirName, 'has wrong owner:', $dirUname, 'vs.', $uname );
            $ret = 0;
        }
    }
    if( defined( $dirGname )) {
        if( $dirGname ne $gname ) {
            $self->myerror( 'Directory', $dirName, 'has wrong group:', $dirGname, 'vs.', $gname );
            $ret = 0;
        }
    }

    return $ret;
}

##
# Tests that a symbolic link exists and points to a certain destination.
# Think "ln -s $target $link"
# $target: the destination of the symlink
# $link: the symlink itself
sub checkSymlink {
    my $self   = shift;
    my $target = shift;
    my $link   = shift;

    my( $uname, $gname, $mode, $localContent ) = $self->{scaffold}->getFileInfo( $link, 1 );
    unless( defined( $uname )) {
        $self->myerror( 'Symbolic link does not exist:', $link );
        return 0;
    }

    my $ret = 1;
    unless( Fcntl::S_ISLNK( $mode )) {
        $self->myerror( 'Not a symlink:', $link );
        $ret = 0;
    }
    my $content = readlink( $link );
    if( $target ne $localContent ) {
        $self->myerror( 'Wrong target for symbolic link:', $target, 'vs.', $localContent );
        $ret = 0;
    }
    return $ret;
}

##### (5) Utility methods #####

##
# Emit a response in the trace level of the log
# $response: the response
sub debugResponse {
    my $response = shift;

    trace( sub { "Response:\n" . UBOS::Utils::hashAsColumns( $response ) } );
}

##
# Report an error.
# @args: error message
sub myerror {
    my $self = shift;
    my @args = @_;

    my $msg = join( ' ', grep { defined( $_ ) && !/^\s*$/ } @args );

    if( $self->{verbose} ) {
        # Only report error at the end if not verbose at all
        UBOS::Logging::error( $msg );
    }

    push @{$self->{errors}}, $msg;

    return $msg;
}

##
# Obtain reported errors and clear the buffer
# return: array of errors; may be empty
sub errorsAndClear {
    my $self = shift;

    my @ret = @{$self->{errors}};
    $self->{errors} = [];

    return @ret;
}

##
# Append an error message to the error messages that may already be
# contained in this response hash
# $hash: the response hash
# $newError: the error message
sub appendError {
    my $hash     = shift;
    my $newError = shift;

    my $error = $hash->{error};
    if( $error ) {
        my $index = 0;
        foreach my $line ( split( "\n", $error ) ) {
            if( $line =~ m!^\s*(\d+):! ) {
                $index = $1;
            }
        }
        if( $index ) {
            $error .= ++$index . ": " . $newError;
        } else {
            $error = "1: $error$newError";
        }

    } else {
        $hash->{error} = $error;
    }
    return $hash;
}

##
# Destroy this context.
sub destroy {
    my $self = shift;

    # could be used to delete cookie files, but right now Perl does this itself
}

1;

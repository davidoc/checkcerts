#!/usr/bin/env perl

use TAP::Harness;
use Getopt::Long;

my @tests;
my @certs;
my $verbose = 0;
my $all = 0;

$IGTF::cert;

GetOptions( "verbose!"=>\$verbose,
            "all!"=>\$all,
            "tests:s{,}"=>\@tests,
            "certs:s{,}"=>\@certs);



if($all) { # run all tests on all certs as a single test run
    my @test_args = @certs;
    my %hargs = (
        verbosity => $verbose,
        test_args => \@test_args,
    );
    my $harness = TAP::Harness->new(\%hargs);
    $harness->runtests(@tests);
} else { # run all tests on each cert seperately
    for my $cert (@certs) {
        my @test_args = ($cert,);
        my %hargs = (
            verbosity => $verbose,
            test_args => \@test_args,
        );
        my $harness = TAP::Harness->new(\%hargs);
        $harness->runtests(@tests);
    }
}

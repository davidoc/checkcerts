#!/usr/bin/env perl

use strict;

use Test::Harness;

use Getopt::Long;
use Pod::Usage;

=head1 NAME

checkcerts.pl - check certificate profiles

=head1 SYNOPSIS

checkcerts.pl [options] --tests [file ...] --certs [file ...]

Options:

   -a --aggregate   aggregate results for all tests on all certs 

   -h --help        brief help message
   -m --man         full documentation
   -v --verbose     verbose output

Flags:

   --tests          one or more test suite files
   --certs          one or more certificate files

=head1 DESCRIPTION

B<checkcerts.pl> runs tests against certificates.
The tests can check aspects of a certificate's profile against requirements
or standards.

=cut

my @tests;
my @certs;
my $verbose = 0;
my $all = 0;
my $help = 0;
my $man = 0;

=head1 OPTIONS

=over 8

=item B<-a --aggregate>

Aggregate results of all supplied tests on all supplied certificates in a
single test run.  This will give an overall C<PASS> or C<FAIL> result, which
may be useful to verify compliance of a set of certicates.

By default (when this option is not specified) each combination of test suite
and certificate gets its own test run and an individual result.

=item B<-h --help>  

Print a brief help message and exits.

=item B<-m --man>   

Prints the manual page and exits.

=item B<-v --verbose>

Produce verbose output. In particular, this will give an individual C<ok>
or C<not ok> result for each test within a test file.

=back

=head1 FLAGS

=over 8

=item B<-t --test --tests>

This flag is used to specify one or more test suites
to apply to certificates. The test suites should use the Test::More module,
or equivalent, to provide test results in the correct form. More details
of the tests are given below.

This flag can appear multiple times.

=item B<-c --cert --certs>

This flag is used to specify one or more certificates
to check. Certificates should be in PEM format.

This flag can appear multiple times.

=back
=cut

GetOptions( "verbose!"=>\$verbose,
            "aggregate!"=>\$all,
            "help!"=>\$help,
            "man!"=>\$man,
            "tests:s{,}"=>\@tests,
            "certs:s{,}"=>\@certs) or pod2usage(2);

pod2usage(1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;

print STDERR "No certificates specified\n" if($#certs < 0); 
print STDERR "No tests specified\n" if($#tests < 0);
pod2usage(2) if($#certs < 0 or $#tests < 0); 

$Test::Harness::Verbose = $verbose;

if($all) { # run all tests on all certs as a single test run
    run_tests_on_certs(@certs);
} else { # run all tests on each cert seperately
    for my $cert (@certs) {
        run_tests_on_certs(($cert,));
    }
}

sub run_tests_on_certs() {
    my @tcerts = @_;
    # Write list of certs to a known file. Can't easily use a temp
    # file  as there is no way to pass the name or handle to the test.
    open CERTS, ">./certs" or die "\n./certs: $!";
    for my $cert (@tcerts) { print CERTS "$cert\n"; }
    close CERTS;
    # Run the tests in "eval" to catch exception.
    eval { runtests(@tests) };
    # currently do nothing with exception
    #warn ($@) if $@;
}

1;
__END__


=head1 TESTS

The structure of a test suite is as follows:

    use Test::More qw( no_plan );

    use Crypt::OpenSSL::X509;

    for my $certfile(@ARGV) {
        ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile),
         "new_from_file $certfile");

        cmp_ok($x509->version, '==', 2, 'version');

        # ... more tests
    }

The tests are written using C<ok>, C<like>, and other test functions
described in the documentation for Test::More.

Note that Crypt::OpenSSL::X509 and any other tools used to examine the
certificates must be used within the test suite itself: checkcerts.pl
only provides a test harness for running the test suites.

=head1 EXAMPLES

Check a CA certificate against test suite:

    checkcerts.pl --test gfd125-ca.t --cert cacert.pem

Check all grid CA certificates against test suite:

    checkcerts.pl --test gfd125-ca.t \
    --certs /etc/grid-security/certificates/*.[0-9]

Check all in a single test run to give aggregate result:

    checkcerts.pl --aggregate --test gfd125-ca.t \
    --certs /etc/grid-security/certificates/*.[0-9]

=head1 NOTES

The supplied test suite C<gfd125-ca.t> makes use of an enhanced version
of Crypt::OpenSSL::X509 that has not yet been incorporated into the 
distributed version. It can temporarily be downloaded from
I<https://www.cs.tcd.ie/David.OCallaghan/Crypt-OpenSSL-X509-0.9.1-TCD.tar.gz>
or a bzr (I<http://bazaar-vcs.org/>) branch can be pulled from 
I<https://www.cs.tcd.ie/David.OCallaghan/crypt-openssl-x509/>.

=cut

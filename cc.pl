#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::OpenSSL::X509;

my $x509 = Crypt::OpenSSL::X509->new_from_file('cert.pem');
#print $x509->subject() . "\n";
my $exts = $x509->extensions_by_oid();

  foreach my $oid (keys %$exts) {
    my $ext = $$exts{$oid};
    print $oid, " ", $ext->object()->name(), ": ", $ext->value(), "\n";
  }



print "\n\nTest has_extension_oid\n";
print "17: " . $x509->has_extension_oid("2.5.29.17") . "\n";
print "32: " . $x509->has_extension_oid("2.5.29.32") . "\n";

print "\n\nCert printout\n";

print $x509->version . "\n";
print $x509->subject . "\n";
#print $x509->subject_alternative_names . "\n";
print $x509->issuer . "\n";
#print $x509->issuer_alternative_names . "\n";
print $x509->notBefore . "\n";
print $x509->notAfter . "\n";
print $x509->serial . "\n";

print $x509->sig_alg_name . "\n";
print $x509->modulus() . "\n";
print $x509->bit_length() . "\n";

my $subj = $x509->subject_name();
my $rdns = $subj->entries();
foreach my $rdn (@$rdns) {
    print $rdn->long_type(), "\t";
    print $rdn->value(), "\n";
}

print "\n", @$rdns[0]->as_string(), "\n";
print "\n", @$rdns[0]->as_long_string(), "\n";

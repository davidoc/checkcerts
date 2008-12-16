#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::OpenSSL::X509;

my $x509 = Crypt::OpenSSL::X509->new_from_file('cert.pem');
#print $x509->subject() . "\n";

my $exs = $x509->extensions_by_name();

my $key;

foreach $key (keys %$exs) {
    my $ex = $$exs{$key};
#    print $ex;
    my $v = $ex->value();
    my $oid = $ex->object()->oid();
    print "$key - $oid:\n  $v\n";
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
print $x509->key_length() . "\n";

#my $c = $x509->extension_count();
#for(my $i = 0; $i < $c; $i++) {
#    my $ex = $x509->extension($i);
#    #my $s = $ex->is_critical()?"Critical":"Not critical";
#    my $obj = $ex->object();
#    my $o = $obj->name();
#    my $oid = $obj->id();
#    my $v = $ex->value();
#    print "$i: $o -- $oid\n  $v\n";
#}
#print $ex;
#use rules;

#cc::run_rules($rules::rules{'ee'}{'common'});
#print %{$rules::rules{'ee'}{'common'}} . "\n";

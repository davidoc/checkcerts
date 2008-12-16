use Test::More qw( no_plan );
use strict;
use warnings;

# Pre-requisites
use_ok("Crypt::OpenSSL::X509");

for my $certfile(@ARGV) {
    ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile), "new_from_file $certfile");

    # Cert version
    cmp_ok($x509->version, '==', 2, 'version 2.1');

    # Serial & Message Digest
    like($x509->serial, qr/[a-fA-F0-9]+/, 'serial 2.2');
    unlike($x509->sig_alg_name, '/md5/i', 'not md5 2.2');
    like($x509->sig_alg_name, '/sha-?1/i', 'sha-1 2.2');

    # Issuer and Subject names

}

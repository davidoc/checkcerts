use Test::More qw( no_plan );
use strict;
use warnings;

# Pre-requisites
use Crypt::OpenSSL::X509;

for my $certfile(@ARGV) {
    ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile), "new_from_file $certfile");

    # Cert version 2.1
    cmp_ok($x509->version, '==', 2, 'version 2.1');

    # Serial & Message Digest 2.2
    like($x509->serial, qr/[a-fA-F0-9]+/, 'serial 2.2');
    unlike($x509->sig_alg_name, '/md5/i', 'not md5 2.2');
    like($x509->sig_alg_name, '/sha-?1/i', 'sha-1 2.2');

    # Issuer and Subject names 2.3
    my $subject_name = $x509->subject_name();
    ok($subject_name->has_entry('CN'), 'DN has CN 2.3');

    my $entries = $subject_name->entries();
    for my $entry (@$entries) {
        ok($entry->is_printableString(), $entry->type() . ' is printableString 2.3') or diag($entry->as_string(), " not printableString");
    }

    #2.3.1 CN should be descriptive
    #2.3.2 should consist of "DC", "C", "ST", "L", "O", "OU" and "CN"
    #2.3.2 if using DC, DCs should be at start
    if($subject_name->has_entry('DC')) {
        my $loc = $subject_name->get_index_by_type('DC');
        is($loc, 0, "DC at start 2.3.2");
        my $oldloc = $loc;
        while($subject_name->has_entry('DC', $oldloc)) {
            my $loc = $subject_name->get_index_by_type('DC', $oldloc);
            next if $oldloc == $loc;
            is($loc, $oldloc+1, "Multiple DCs at start 2.3.2");
            $oldloc = $loc;
        }
    }
    #2.3.2 DN should have O
    #2.3.2 C should match issuer
    #isa($x509->subject, "ASN1_SEQUENCE", 'DN is ASN1 SEQUENCE 2.3');

    ok(not($subject_name->has_long_entry('serialNumber')), 'DN does not have serialNumber 2.3.3');
    ok(not($subject_name->has_long_entry('emailAddress')), 'DN does not have emailAddress 2.3.4');
    ok(not($subject_name->has_entry('UID')), 'DN does not have UID 2.3.5');
    ok(not($subject_name->has_oid_entry('0.9.2342.19200300.100.1.1')), 'DN does not have userID 2.3.5');
    
    # Extensions in CA certificates 2.4
    my $exts = $x509->extensions_by_name();
    ok($$exts{'X509v3 Basic Constraints'}, 'Has basicConstraints 2.4.1');
    #is($$exts{'basicConstraints}->value(), "CA: TRUE", 'basicConstraints CA: TRUE 2.4.1');
    ok($$exts{'X509v3 Basic Constraints'}->critical(), 'basicConstraints is critical 2.4.1');
    ok($$exts{'X509v3 Key Usage'}, 'Has keyUsage 2.4.2');
    ok($$exts{'X509v3 Key Usage'}->critical(), 'keyUsage is critical 2.4.2');
}

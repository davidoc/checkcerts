##
## Test Suite for CA Certificates under GFD-C.125 "Grid Certificate Profile"
##
## David O'Callaghan <david.ocallaghan@cs.tcd.ie>
## 2009-01-27
## VERSION 0.1.3
##
## TODO: implementation is incomplete
##

# Pre-requisites
use CheckCertsTest;

for my $certfile(@certlist) {
    ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile), "new_from_file $certfile");
    diag "\n\n * * * \nCert Subject: ", $x509->subject, "\n";
    ok($x509->subject, "Subject: " . $x509->subject);

    # Cert version 2.1
    cmp_ok($x509->version, '==', 2, 'Version value MUST be "2" per X.509v3 (2.1)');

    # Serial & Message Digest 2.2
    #like($x509->serial, qr/[a-fA-F0-9:]+/, 'Serial number format (2.2)');
    #TODO serial number SHOULD be > 0
    unlike($x509->sig_alg_name, '/md5/i', 'Message digest MUST NOT be MD5 in new CA certs (2.2)');
    like($x509->sig_alg_name, '/sha-?1/i', 'Message digest SHOULD be SHA-1 (2.2)');

    # Issuer and Subject names 2.3
    my $subject_name = $x509->subject_name();
    ok($subject_name->has_entry('CN'), 'CA certificate SHOULD have CN in DN (2.3.1)');

    # Name components should be printableString
    # DC and emailAddress should be ia5String
    my $entries = $subject_name->entries();
    for my $entry (@$entries) {
        if( is_member($entry->type(), ("DC","emailAddress") )) {    
            ok($entry->is_ia5string(), $entry->type() . ' SHOULD be ia5String (!2.3)');
        } else {
            ok($entry->is_printableString(), $entry->type() . ' SHOULD be printableString (2.3)');
        }
    }

    #2.3.1 CN should be descriptive
    #2.3.2 should consist of "DC", "C", "ST", "L", "O", "OU" and "CN"
    #2.3.2 if using DC, DCs should be at start
    if($subject_name->has_entry('DC')) {
        my $loc = $subject_name->get_index_by_type('DC');
        is($loc, 0, "DC is at start of DN (2.3.2)");
        my $oldloc = $loc;
        while($subject_name->has_entry('DC', $oldloc)) {
            my $loc = $subject_name->get_index_by_type('DC', $oldloc);
            next if $oldloc == $loc;
            is($loc, $oldloc+1, "Multiple DCs are at start of DN (2.3.2)");
            $oldloc = $loc;
        }
    }
    #2.3.2 DN should have O
    #2.3.2 C should match issuer
    #isa($x509->subject, "ASN1_SEQUENCE", 'DN is ASN1 SEQUENCE 2.3');

    ok(not($subject_name->has_long_entry('serialNumber')), 'serialNumber SHOULD NOT be used in DN (2.3.3)');
    ok(not($subject_name->has_long_entry('emailAddress')), 'emailAddress SHOULD NOT be used in DN(2.3.4)');
    ok(not($subject_name->has_entry('UID')), 'DN does not have UID (2.3.5)');
    ok(not($subject_name->has_oid_entry('0.9.2342.19200300.100.1.1')), 'DN does not have userID (2.3.5)');
    
    # Extensions in CA certificates 2.4
    my $exts = $x509->extensions_by_name();
    ok($$exts{'basicConstraints'}, 'CA cert MUST include basicConstraints (2.4.1)');
    # TODO is($$exts{'basicConstraints}->value(), "CA: TRUE", 'basicConstraints CA: TRUE 2.4.1');
    $$exts{'basicConstraints'} and ok($$exts{'basicConstraints'}->critical(), 'basicConstraints SHOULD be marked critical (2.4.1)'); 
    ok($$exts{'keyUsage'}, 'CA cert MUST include keyUsage (2.4.2)');
    $$exts{'keyUsage'} and ok($$exts{'keyUsage'}->is_critical(), 'keyUsage SHOULD be marked critical (2.4.2)');
    # extendedKeyUsage 2.4.3
    ok(!($$exts{'extendedKeyUsage'}), "CA cert SHOULD NOT include extendedKeyUsage (2.4.3)");
    $$exts{'extendedKeyUsage'} and 
        ok(not($$exts{'extendedKeyUsage'}->critical()), "extendedKeyUsage MUST NOT be marked critical (2.4.3)");
    # nsCertType, nsComment, nsPolicyURL, nsRevocationURL 2.4.4
    foreach my $ext ("nsCertType", "nsComment", "nsPolicyURL", "nsRevocationURL"){
        ok(not($$exts{$ext}), "CA cert SHOULD NOT include $ext extension (2.4.4)");
        $$exts{$ext} and ok(!($$exts{$ext}->critical()), "$ext MUST NOT be marked critical (2.4.4)");
    }
    # TODO If nsCertType is used, it MUST be consistent with the keyUsage extension.
    
    # certificatePolicies 2.4.5
    $$exts{'certificatePolicies'} and
        ok(not($$exts{'certificatePolicies'}->critical()), "certificatePolicies extension SHOULD NOT be marked critical (2.4.5)");

    # TODO cRLDistributionPoints 2.4.6
    if($$exts{'crlDistributionPoints'}) {
        # TODO 
    }
    # Authority and Subject Key Identifier 2.4.7




}

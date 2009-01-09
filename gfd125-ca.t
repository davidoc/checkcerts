##
## Test Suite for CA Certificates under GFD-C.125 "Grid Certificate Profile"
##
## David O'Callaghan <david.ocallaghan@cs.tcd.ie>
## 2009-01-09
## VERSION 0.1.2
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
    cmp_ok($x509->version, '==', 2, 'version 2.1');

    # Serial & Message Digest 2.2
    like($x509->serial, qr/[a-fA-F0-9:]+/, 'Serial number format 2.2');
    unlike($x509->sig_alg_name, '/md5/i', 'Message digest MUST NOT be md5 in new CA certs 2.2');
    like($x509->sig_alg_name, '/sha-?1/i', 'Message digest SHOULD be sha-1 2.2');

    # Issuer and Subject names 2.3
    my $subject_name = $x509->subject_name();
    ok($subject_name->has_entry('CN'), 'DN has CN 2.3');

    my $entries = $subject_name->entries();
    for my $entry (@$entries) {
        ok($entry->is_printableString(), $entry->type() . ' is printableString 2.3') or diag("Name component ", $entry->as_string(), " SHOULD be printableString")
            unless $entry->type() eq "DC";
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
    ok($$exts{'basicConstraints'}, 'Has basicConstraints 2.4.1');
    # TODO is($$exts{'basicConstraints}->value(), "CA: TRUE", 'basicConstraints CA: TRUE 2.4.1');
    ok($$exts{'basicConstraints'}->critical(), 'basicConstraints critical 2.4.1') or
        diag("basicConstraints SHOULD be marked critical in CA certificates");
    ok($$exts{'keyUsage'}, 'Has keyUsage 2.4.2');
    ok($$exts{'keyUsage'}->is_critical(), 'keyUsage critical 2.4.2') or
        diag("keyUsage SHOULD be marked critical in CA certificates");
    # extendedKeyUsage 2.4.3
    ok(!($$exts{'extendedKeyUsage'}), "No extendedKeyUsage 2.4.3") or
        diag("CA certificates SHOULD NOT include extendedKeyUsage extension");
    if($$exts{'extendedKeyUsage'}) {
        ok(not($$exts{'extendedKeyUsage'}->critical()), "extendedKeyUsage not critical 2.4.3") or 
            diag("extendedKeyUsage MUST NOT be marked critical in CA certificates");
    }
    # nsCertType, nsComment, nsPolicyURL, nsRevocationURL 2.4.4
    foreach my $ext ("nsCertType", "nsComment", "nsPolicyURL", "nsRevocationURL"){
        ok(not($$exts{$ext}), "No $ext 2.4.4") or
            diag("CA certificates SHOULD NOT include $ext extension");
        if($$exts{$ext}) {
            ok(!($$exts{$ext}->critical()), "$ext not critical 2.4.4") or 
                diag("$ext MUST NOT be marked critical in CA certificates");
        }
    }
    # TODO If nsCertType is used, it MUST be consistent with the keyUsage extension.
    
    # certificatePolicies 2.4.5
    if($$exts{'certificatePolicies'}) {
        ok(not($$exts{'certificatePolicies'}->critical()), "certificatePolicies not critical 2.4.5") or diag("certificatePolicies extension SHOULD NOT be marked critical if present");
    }

    # TODO cRLDistributionPoints 2.4.6
    if($$exts{'crlDistributionPoints'}) {
        # DO 
    }
    # Authority and Subject Key Identifier 2.4.7




}

##
## Test Suite for CA Certificates under GFD-C.125 "Grid Certificate Profile"
##
## David O'Callaghan <david.ocallaghan@cs.tcd.ie>
## 2010-01-07
##

# Pre-requisites
use CheckCertsTest;

for my $certfile(@certlist) {
    ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile), "(Info) new_from_file $certfile");
    diag "\n\n * * * \nCert Subject: ", $x509->subject, "\n", "Cert file: ", $certfile, "\n";
    ok($x509->subject, "(Info) Subject: " . $x509->subject);

    # Cert version 2.1
    cmp_ok($x509->version, '==', 2, '(2.1) Version value MUST be "2" per X.509v3');

    # Serial & Message Digest 2.2
    # Check if serial number changed on update
    SKIP: {
        fail('(2.2a Manual Check) Serial number SHOULD be unique among all CA certs representing the CA');
    }
    unlike($x509->serial, qr/^0+$/,'(2.2xa) Serial number should not be 0') or
    (abs($x509->serial+0) != 0) and ok(($x509->serial+0 == abs($x509->serial+0)), '(2.2xb) Serial number should be > 0');
    like($x509->serial, qr/[a-fA-F0-9:]+/, '(2.2xc) Serial  number format');
    SKIP: {
        fail('(2.2b Manual Check) If EE certs contain authorityKeyIdentifier including CA serial, serial SHOULD remain the same on re-issuing CA certificate.');
        fail('(2.2c EE Check) CA serial in EE authorityKeyIdentifier is NOT RECOMMENDED.');
    }
    unlike($x509->sig_alg_name, '/md5/i', '(2.2d) Message digest MUST NOT be MD5 in new CA certs');
    like($x509->sig_alg_name, '/sha-?1/i', '(2.2e) Message digest SHOULD be SHA-1 ');

    # Issuer and Subject names 2.3
    my $subject_name = $x509->subject_name();
    TODO: {
        fail("(2.3c TODO) the ASN.1 SEQUENCE MUST only contain SETs of length 1");
        fail("(2.3d TODO) All RDNs MUST be compliant with RFC 4630");
    }

    #2.3.1 CN should be descriptive
    ok($subject_name->has_entry('CN'), '(2.3.1) CA certificate SHOULD have CN in DN');
    SKIP: {
        fail("(2.3.1a Manual Check) CA certificate CN SHOULD be an explicit string distinguishing the authority's name");
    }

    my $entries = $subject_name->entries();
    for my $entry (@$entries) {
        #2.3.2 should consist of "DC", "C", "ST", "L", "O", "OU" and "CN"
        ok(is_member($entry->type(), ("DC","C","ST","L","O","OU","CN")), "(2.3.2) DN SHOULD NOT contain entries other than DC, C, ST, L, O, OU, CN (Type: " . $entry->type() . ")");
        if( is_member($entry->type(), ("DC","emailAddress") )) {    
            # DC and emailAddress should be ia5String
            ok($entry->is_ia5string(), "(3.2.4) " . $entry->type() . ' SHOULD be ia5String (It is actually: ' . $entry->encoding . ')');
        } else {
            # Name components should be printableString
            ok(($entry->is_printableString() or $entry->is_utf8string()), "(2.3) " . $entry->type() . ' SHOULD be printableString or, if not, utf8string (It is actually: ' . $entry->encoding . ')');
            TODO: {
                #isa($x509->subject, "ASN1_SEQUENCE", 'DN is ASN1 SEQUENCE 2.3');
                #ASN sequence MUST only contain SET's of length 1
                fail("(2.3f TODO) RDNs encoded in UTF8String MUST NOT contain characters that cannot be expressed in printable 7-bit ASCII");
            }
        }
    }



    #2.3.2 if using DC, DCs should be at start
    if($subject_name->has_entry('DC')) {
        my $loc = $subject_name->get_index_by_type('DC');
        is($loc, 0, "(2.3.2c) DC MUST be at start of DN, if DC used");
        my $oldloc = $loc;
        while($subject_name->has_entry('DC', $oldloc)) {
            my $loc = $subject_name->get_index_by_type('DC', $oldloc);
            next if $oldloc == $loc;
            is($loc, $oldloc+1, "(2.3.2c) Multiple DCs MUST be at start of DN, if DC used");
            $oldloc = $loc;
        }
    }

    ok($subject_name->has_entry('O'), '(2.3.2d) DN SHOULD contain O');
    #2.3.2 C should match issuer
    SKIP: {
        fail('(2.3.2e Manual Check) if CN contains C it should match the Issuer country');
    }
    ok(not($subject_name->has_long_entry('serialNumber')), '(2.3.3) serialNumber MUST NOT be used in DN');
    ok(not($subject_name->has_long_entry('emailAddress')), '(2.3.4) emailAddress SHOULD NOT be used in DN');
    ok(not($subject_name->has_entry('UID')), '(2.3.5) UID MUST NOT be used in DN');
    ok(not($subject_name->has_oid_entry('0.9.2342.19200300.100.1.1')), '(2.3.5) userID MUST NOT be used in DN');

    # Extensions in CA certificates 2.4
    my $exts = $x509->extensions_by_name();

    # basicConstraints 2.4.1
    ok($$exts{'basicConstraints'}, '(2.4.1a) CA cert MUST include basicConstraints');
    ok(($$exts{'basicConstraints'} && $$exts{'basicConstraints'}->basicC("ca")), '(2.4.1b) basicConstraints MUST be set to "CA: TRUE"');
    ok(($$exts{'basicConstraints'} && $$exts{'basicConstraints'}->critical()), '(2.4.1c) basicConstraints SHOULD be marked critical'); 

    # keyUsage 2.4.2
    ok($$exts{'keyUsage'}, '(2.4.2a) CA cert MUST include keyUsage');
    ok(($$exts{'keyUsage'} and  $$exts{'keyUsage'}->is_critical()), '(2.4.2b) keyUsage SHOULD be marked critical');
    # For a CA cert, keyCertSign must be set and TODO crlSign must be set if the CA cert is used to directly issue crls
    $$exts{'keyUsage'} and my %key_hash = $$exts{'keyUsage'}->hash_bit_string();
    $$exts{'keyUsage'} and ok($key_hash{'Certificate Sign'}, '(2.4.2c) keyCertSign MUST be set');
    
    TODO:{
    $$exts{'keyUsage'} and ok($key_hash{'CRL Sign'}, '(2.4.2d MANUAL) crlSign MUST be set, if CA cert used directly to sign CRLs');
    }
    ### === REFACTORING HORIZON === ###
    # extendedKeyUsage 2.4.3
    ok(not($$exts{'extendedKeyUsage'}), "CA cert SHOULD NOT include extendedKeyUsage (2.4.3)");
    $$exts{'extendedKeyUsage'} and 
    ok(not($$exts{'extendedKeyUsage'}->critical()), "extendedKeyUsage MUST NOT be marked critical (2.4.3)");
    # nsCertType, nsComment, nsPolicyURL, nsRevocationURL 2.4.4
    foreach my $ext ("nsCertType", "nsComment", "nsPolicyURL", "nsRevocationURL"){
        ok(not($$exts{$ext}), "CA cert SHOULD NOT include $ext extension (2.4.4)");
        $$exts{$ext} and ok(not($$exts{$ext}->critical()), "$ext MUST NOT be marked critical (2.4.4)");
    }

    # nsCertType 2.4.4
    if($$exts{'nsCertType'}){
        my %ns_hash = $$exts{'nsCertType'}->hash_bit_string();
        $ns_hash{'SSL Client'} || $ns_hash{'S/MIME CA'} || $ns_hash{'Object Signing CA'} and
        ok($key_hash{'Digital Signature'},
            "The SSL Client, S/MIME CA and Object Signing CA attributes in nsCertType require the Digital Signature attribute of keyUsage. 
            If used, nsCertType MUST be consistent with the keyUsage extension (2.4.4)");

        $ns_hash{'SSL CA'} and
        ok($key_hash{'Certificate Sign'}, 
            "The SSL CA attribute of nsCertType requires the keyCertSign attribute of keyUsage. 
            If used, nsCertType MUST be consistent with the keyUsage extension (2.4.4)");
    }

    # certificatePolicies 2.4.5
    $$exts{'certificatePolicies'} and
    ok(not($$exts{'certificatePolicies'}->critical()), "certificatePolicies extension SHOULD NOT be marked critical (2.4.5)");

    # crlDistributionPoints 2.4.6
    # Should be in any end-entity and intermediate (not self-signed) CA certs that issue CRLs.
    if($key_hash{'CRL sign'} and not($x509->subject eq $x509->issuer)){
        ok($$exts{'crlDistributionPoints'}, 'Should be in any intermediate (not self-signed) CA certs that issue CRLs (2.4.6)')
    }
    # For subordinate CAs, where CDP is present, it must contain at least one http URI
    $$exts{'crlDistributionPoints'} and not($x509->subject eq $x509->issuer) and 
    like($$exts{'crlDistributionPoints'}->to_string(), qr/http:(.+)/, "In subordinate CAs, a CDP must contain at least one http URI (2.4.6)");

    # Authority and Subject Key Identifier 2.4.7
    ok($$exts{'subjectKeyIdentifier'}, "Subject Key Identifier must be included in CA certs (2.4.7)");

    # TODO check properly if the cert is self-signed, rather than checking the issuer and subject
    # If cert is self-signed i.e. it's signed with its own key, the signature matches the public key (or the issuer==subject)
    if(not($x509->subject eq $x509->issuer)){
        ok($$exts{'authorityKeyIdentifier'}, "If the cert is not self-signed, an Authority Key Identifier must be included (2.4.7)");
    }
    # The cert is self-signed, the authorityKeyIdentifier's keyid must be the same as subjectkeyIdentifier
    else{
        my ($subkeyid, $authkeyid);
        $$exts{'subjectKeyIdentifier'} and	$subkeyid = (join ":", map{sprintf "%X", ord($_)} split //, $$exts{'subjectKeyIdentifier'}->keyid_data());
        $$exts{'authorityKeyIdentifier'} and	$authkeyid = (join ":", map{sprintf "%X", ord($_)} split //, $$exts{'authorityKeyIdentifier'}->keyid_data());;
        if($subkeyid and $authkeyid) {
            like($authkeyid, qr/$subkeyid/, "The keyid of authorityKeyIdentifier should be the same as subjectKeyIdentifer (2.4.7)");
        }
    }
    # If AKID exists, only the keyIdentifier attribute should be included
    $$exts{'authorityKeyIdentifier'} and 
    ok($$exts{'authorityKeyIdentifier'}->auth_att, "If authorityKeyIdentifier exists, only the keyid attribute should be included (2.4.7)");

    # nameConstraints 2.4.8
    ok(not($$exts{'nameConstraints'}), "The use of nameConstraints is not recommended (2.4.8)");
}

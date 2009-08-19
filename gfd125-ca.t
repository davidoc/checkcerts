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
    like($x509->serial, qr/[a-fA-F0-9:]+/, 'Serial  number format (2.2)');
    like($x509->serial, qr/0+/,'Serial number should not be 0');
    (abs($x509->serial+0) != 0) and ok(($x509->serial+0 eq abs($x509->serial+0)), 'Serial number should be > 0');
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
	#ASN sequence MUST only contain SET's of length 1
    ok(not($subject_name->has_long_entry('serialNumber')), 'serialNumber SHOULD NOT be used in DN (2.3.3)');
    ok(not($subject_name->has_long_entry('emailAddress')), 'emailAddress SHOULD NOT be used in DN(2.3.4)');
    ok(not($subject_name->has_entry('UID')), 'DN MUST NOT have UID (2.3.5)');
    ok(not($subject_name->has_oid_entry('0.9.2342.19200300.100.1.1')), 'DN MUST NOT have userID (2.3.5)');
    
    # Extensions in CA certificates 2.4
    my $exts = $x509->extensions_by_name();

	# basicConstraints 2.4.1
    ok($$exts{'basicConstraints'}, 'CA cert MUST include basicConstraints (2.4.1)');
	ok($$exts{'basicConstraints'}->basicC("ca"), 'basicConstraints CA: TRUE 2.4.1');
    $$exts{'basicConstraints'} and ok($$exts{'basicConstraints'}->critical(), 'basicConstraints SHOULD be marked critical (2.4.1)'); 
	
	# keyUsage 2.4.2
    ok($$exts{'keyUsage'}, 'CA cert MUST include keyUsage (2.4.2)');
    $$exts{'keyUsage'} and ok($$exts{'keyUsage'}->is_critical(), 'keyUsage SHOULD be marked critical (2.4.2)');
	# For a CA cert, keyCertSign must be set and crlSign must be set if the CA cert is used to directly issue crls
	$$exts{'keyUsage'} and my %key_hash = $$exts{'keyUsage'}->hash_bit_string();
	ok($key_hash{'Certificate Sign'}, 'For a CA cert, keyCertSign must be set (2.4.2)');


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
	if($$exts{'basicConstraints'}->basicC("ca")){
		ok($$exts{'subjectKeyIdentifier'}, "Subject Key Identifier must be included in CA certs (2.4.7)");
	}
	
	# TODO check properly if the cert is self-signed, rather than checking the issuer and subject
    # If cert is self-signed i.e. it's signed with its own key, the signature matches the public key (or the issuer==subject)
	if(not($x509->subject eq $x509->issuer)){
		ok($$exts{'authorityKeyIdentifier'}, "If the cert is not self-signed, an Authority Key Identifier must be included (2.4.7)");
	}
	# The cert is self-signed, the authorityKeyIdentifier's keyid must be the same as subjectkeyIdentifier
	else{
		my $subkeyid = (join ":", map{sprintf "%X", ord($_)} split //, $$exts{'subjectKeyIdentifier'}->keyid_data());
		my $authkeyid = (join ":", map{sprintf "%X", ord($_)} split //, $$exts{'authorityKeyIdentifier'}->keyid_data());;
		like($authkeyid, qr/$subkeyid/, "The keyid of authorityKeyIdentifier should be the same as subjectKeyIdentifer (2.4.7)");
	}
	# If AKID exists, only the keyIdentifier attribute should be included
	$$exts{'authorityKeyIdentifier'} and 
		ok($$exts{'authorityKeyIdentifier'}->auth_keyid, "If authorityKeyIdentifier exists, only the keyid attribute should be included (2.4.7)");
	
	# nameConstraints 2.4.8
	ok(not($$exts{'nameConstraints'}), "The use of nameConstraints is not recommended (2.4.8)");
}

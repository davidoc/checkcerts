##
## Test Suite for End Entity Certificates under GFD-C.125 "Grid Certificate Profile"
## 
## 2009-07-29
## 
## TODO: implementation not complete
##

#Pre-requisites
use CheckCertsTest;

for my $certfile (@certlist) {
    ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile), "new_from_file $certfile");
    diag "\n\n * * * \nCert Subject: ", $x509->subject, "\n";
    ok($x509->subject, "Subject: " . $x509->subject);

	# Cert version, serial number and message digest 3.1
	cmp_ok($x509->version, "==", 2, 'Version number must be "2" as per X509v3 (3.1)');
	like($x509->serial, qr/[a-fA-F0-9:]+/, 'Serial  number format (3.1)');
    # serial number should be >0
    unlike($x509->sig_alg_name, '/md5/i', 'Message digest MUST NOT be MD5 in new EE certs (3.1)');
    like($x509->sig_alg_name, '/sha-?1/i', "Message digest SHOULD be SHA-1 (3.1)");

	# Subject Distinguished Names 3.2
	my $subject_name = $x509->subject_name();
    ok($subject_name->has_entry('CN'), 'End entity certificates MUST include CN in DN (3.2.3)');
	
    # Common Name component should be encoded as printableString,
	# otherwise it should be encoded as UTF8String.
    my $entries = $subject_name->entries();
    for my $entry (@$entries) {
        if( is_member($entry->type(), ("CN") )) {
            ok($entry->is_printableString(), $entry->type() . ' SHOULD be printableString (3.2.3)');
        } else {
            ok($entry->is_utf8string(), $entry->type() . ' SHOULD be utf8string (3.2.3)');
        }
    }

	# 3.2.3 For certificates issued to networked entities, typically the (primary) FQDN of the server
	# is included in the commonName. For regular network entity certificates, there MUST NOT 
	# be any additional characters in the commonName.
	
	# 3.2.4 If using DC, DCs should be at the start
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
	
	# 3.2.4 If the C (country) attribute is used, its value SHOULD contain the two-letter
	# ISO3166 encoding of the country's name.
	# 3.2.4 Country must be used at most once
	if($subject_name->has_entry('C')){
		my $loc = $subject_name->get_index_by_type('C');
        my $oldloc = $loc;
        while($subject_name->has_entry('DC', $oldloc)) {
            my $loc = $subject_name->get_index_by_type('DC', $oldloc);
            next if $oldloc == $loc;
            cmp_ok($loc, ">",  $oldloc, 'C must be used at most once (3.2.4)');
            $oldloc = $loc;
        }
    }

	ok($subject_name->has_entry('O'), 'The use of at least one O attribute is recommended (3.2.4)');
	ok(not($subject_name->has_long_entry('serialNumber')), 'serialNumber MUST NOT be used in DN (3.2.5)');
    ok(not($subject_name->has_long_entry('emailAddress')), 'emailAddress SHOULD NOT be used in DN(3.2.6)');
    ok(not($subject_name->has_entry('UID')), 'DN does not have UID (3.2.7)');
    ok(not($subject_name->has_oid_entry('0.9.2342.19200300.100.1.1')), 'DN does not have userID (3.2.7)');

	# Extensions in end entity certificates 3.3
	my $exts = $x509->extensions_by_name();
	
	# basicConstraints 3.3.1
    if($$exts{'basicConstraints'}){
		ok(not($$exts{'basicConstraints'}->basicC("ca")), 'basicConstraints CA:FALSE 3.3.1');
		is($$exts{'basicConstraints'}->basicC("pathlen"), 0, 'pathlenConstraint attribute must not be present(3.3.1)');
		ok($$exts{'basicConstraints'}->critical(), 'basicConstraints MUST be marked critical (3.3.1)');
	}
	
	# keyUsage 3.3.2
	ok($$exts{'keyUsage'}, 'EE cert MUST include keyUsage (3.3.2)');
	$$exts{'keyUsage'} and ok($$exts{'keyUsage'}->is_critical(), 'keyUsage MUST be marked as critical (3.3.2)');

	# extendedKeyUsage 3.3.3
	ok($$exts{'extendedKeyUsage'}, 'EE certs SHOULD include extendedKeyUsage (3.3.3)');
	$$exts{'extendedKeyUsage'} and 
		ok(not($$exts{'extendedKeyUsage'}->critical()), "extendedKeyUsage MUST NOT be marked as critical (3.3.3)");
	# If extKeyUsage and nsCertType are both included the cert purpose in both extensions must be equivalent

	# 3.3.4 Either of extKeyUsage and nsCertType MUST be present to ensure correct operation of grid and other software.
	ok($$exts{'extendedKeyUsage'} or $$exts{'nsCertType'}, "Either of extendedKeyUsage and nsCertType MUST be present");

	# nsCertType 3.3.5
	# TODO consistency checking with extendedKeyUsage
	ok(not($$exts{'nsCertType'}),"It is recommended not to use nsCertType in new certificates (3.3.5)");
	$$exts{'nsCertType'} and ok(not($$exts{'nsCertType'}->critical()), "nsCertType MUST NOT be marked critical (3.3.5)");

	# nsPolicyURL, nsRevocationURL 3.3.6
	foreach my $ext ("nsPolicyURL", "nsRevocationURL"){
        ok(not($$exts{$ext}), "$ext extension is not required in EE certs (3.3.6)");
        $$exts{$ext} and ok(!($$exts{$ext}->critical()), "$ext MUST NOT be marked critical (3.3.6)");
    }
	
	# nsComment 3.3.7
	$$exts{'nsComment'} and 
		ok(not($$exts{'nsComment'}->critical()), "nsComment MUST NOT be marked as critical (3.3.7)");

	# cRLDistributionPoints 3.3.8
	ok($$exts{'crlDistributionPoints'}, "cRLDistributionPoints MUST be present in end-entity certs (3.3.8)");
	$$exts{'crlDistributionPoints'} and 
		like($$exts{'crlDistributionPoints'}->to_string(), qr/http:(.+)/, "The cRLDistributionPoints extension must contain at least one http URI (3.3.8)");
	#crlDistributionPoints must return the CRL in DER encoded form

	# authorityKeyIdentifier 3.3.9
	$$exts{'authorityKeyIdentifier'} and ok(not($$exts{'authorityKeyIdentifier'}->critical()), 
"authorityKeyIdentifier extension MUST NOT be marked as critical (3.3.9)");

	# subjectKeyIdentifier 3.3.10
	$$exts{'subjectKeyIdentifier'} and ok(not($$exts{'subjectKeyIdentifier'}->critical()), "subjectKeyIdentifier MUST NOT be marked as critical (3.3.10)");

	# certificatePolicies 3.3.11
	ok($$exts{'certificatePolicies'}, "certificatePolicies extension MUST be present (3.3.11)");
	$$exts{'certificatePolicies'} and ok(not($$exts{'certificatePolicies'}->critical(), "certificatePolicies MUST NOT be marked critical (3.3.11)"));
	# certificatePolicies MUST contain at least one policy OID. 

	# subjectAlternativeName, issuerAlternativeName 3.3.12
	# TODO subjectAlternativeName should be present for server certs and, if present, MUST contain 
	# at least one FQDN in the dNSNAME attribute.
	# TODO If an EE cert needs to contain an rfc822 email address,this rfc822 address SHOULD be included as an rfc822Name attribute in this extension only.

	
	# authorityInformationAccess 3.3.13
	# TODO It is recommended to include this extension if the issuer operates a production-quality OSCP
	# service. 
	# The extension MUST NOT be included if the value points to an experimental or non-monitored 
	# service, as this will impair operations as soon as an OCSP client is implemented and enabled 
	# in the software.
	$$exts{'authorityInformationAccess'} and ok(not($$exts{'authorityInformationAccess'}->critical()), 
		   "authorityInformationAccess extension MUST NOT be marked critical (3.3.13)");

}
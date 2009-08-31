# Test suite for CA certificates under IGTF RAT Audit 2009-01
# 
# Check new certificate requests for RSA keys with weak exponents (< 65537)
# Check new certificate requests for known weak Debian OpenSSL keys
# Verify new certificates and CRLs are not issued using MD5
# 
# Check PEM certificates for (EC)DSA and MD5
# 
# openssl x509 -text -in $file | egrep -H 'DSA-Parameters|ECDSA-Parameters|DSA Public Key|Algorithm: md5' > /dev/null 2>&1;
# if [$? = "0"]; then 
# echo "$file matches" 
# fi
# 
# Check PEM CRLs for MD5
# 
# openssl crl -text -in $file | egrep -H 'Algorithm: md5' > /dev/null 2>&1;
# 
# Check PEM certificates for Debian keys
# 
# Check PEM certificates with weak RSA exponents
# 

use CheckCertsTest;
for my $certfile(@certlist) {
	ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile), "new_from_file $certfile");
	diag "\n\n * * * \nCert Subject: ", $x509->subject, "\n";

	# Check PEM certificates for (EC)DSA and MD5
	
	unlike($x509->pubkey_type(), '/dsa/', "Public key should not use DSA");
	unlike($x509->sig_alg_name, '/md5/i', "MD5 should not be used.");
	
	# Check PEM CRLs for MD5
	
	# Check for Debian Keys
	my $blacklist = "/usr/share/openssl-blacklist/";
	my $mod = $x509->modulus();
	my $tag=`echo $mod | sha1sum | cut -d ' ' -f 1 | cut -c21-41`;
	ok(not(`fgrep '$tag' $blacklist/"blacklist.RSA-1024"`), "$certfile has blacklisted modulus checksum") or
		ok(not(`grep '$tag' $blacklist/"blacklist.RSA-2048"`), "$certfile has blacklisted modulus checksum");

	
	# Weak RSA exponents
	cmp_ok(hex $x509->pub_exponent, "<=", 65537, "The public exponent should not be less than 65537.");
	
	












}



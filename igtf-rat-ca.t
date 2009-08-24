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
# tag=`openssl x509 -noout -modulus -in $file | sha1sum | cut -d ' ' -f 1 | cut -c21-41`;
# serial=`basename $file .pem
# if [ `fgrep -c $tag /tmp/blacklist.RSA-1024` \
#		-ne 0 -o \
#		`fgrep -c tag /tmp/blacklist.RSA-2048 
#		-ne 0 ] ; then
#	dn=`openssl x509 -noout -subject -in $file | sed -e 's/subject= //'`;
#	caid=`awk '/Tag:/ {print $NF}' $f`;
#	echo "$serial $caid $dn" ;
# fi;
# 
# Check PEM certificates with weak RSA exponents
# 
# exponent=`openssl x509 -in $file -noout -pubkey | openssl rsa -pubin -text -noout | grep Exponent | awk '{print $2}'`
# if [ "$exponent" -lt 65537 ]; then
# 		echo "Weak exponent: $exponent in $file"
# fi
# 

use CheckCertsTest;
for my $certfile(@certlist) {
	ok(my $x509 = Crypt::OpenSSL::X509->new_from_file($certfile), "new_from_file $certfile");
	diag "\n\n * * * \nCert Subject: ", $x509->subject, "\n";

	# Weak RSA exponents
	cmp_ok(hex $x509->pub_exponent, "<=", 65537, "The public exponent should not be less than 65537");
	













}



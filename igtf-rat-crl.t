#
# Test suite for CRLs under IGTF RAT Audit 2009-01
# Verify new certificates and CRLs are not issued using MD5
#


use CheckCertsTest;
for my $certfile(@certlist) {
	ok(my $crl = Crypt::OpenSSL::X509_CRL->new_from_crl_file($certfile), "new_from_file $certfile");
	
    # Check PEM CRLs for MD5
	unlike(Crypt::OpenSSL::X509_CRL::CRL_sig_alg_name($crl), '/md5/i', "Signature Algorithm should not use MD5.");
}

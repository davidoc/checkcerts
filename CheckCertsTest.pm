#package CheckCertTest;

use Test::More qw(no_plan);
use strict;
use warnings;

# Pre-requisites
use Crypt::OpenSSL::X509 1.7;
use Set::Scalar;

our @certlist = ();
open CERTS, "./certs" or die "\n./certs: $!";
while(<CERTS>) {
    chomp;
    push @certlist, $_;
}
close CERTS;

sub is_member($@) {
    my ($target,@list) = @_;
    return (grep {"$_" eq "$target"} @list);
}

sub set_from_hash($) {
    my ($hash_ref) = @_;
    my $result = [];
    while(my ($key,$val) = each(%$hash_ref)) {
        push(@$result,$key) if $val;
    }
    return Set::Scalar->new(@$result);
}

*{Set::Scalar::new_from_hash} = sub {
    my ($class,$hash_ref) = @_;
    return set_from_hash($hash_ref); 
};

sub set_to_string($) {
    my ($set) = @_;
    return '{' . join(", ", $set->elements) . '}';
}

1;

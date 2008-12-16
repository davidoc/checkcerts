package cc;
use Crypt::OpenSSL::X509;


sub run_rules($) {
    my ($ruleset) = @_;
    map_rules($ruleset,run_rule);
}

sub print_rules($) {
    my ($ruleset) = @_;
    map_rules($ruleset,print_rule);
}

sub map_rules($$) {
    my ($ruleset,$func) = @_;
    my $rulename;
    foreach $rulename (sort keys %{$ruleset}) {
        my $rulesub = $ruleset{$rulename};
        &$func($rulename,$rulesub);
    }
}

sub run_rule($$) {
    my ($name,$sub) = @_;
    print "$name: ";
    if(not $sub){
        print "FAIL - not defined"
    } else {
        &$sub and print "OK" or print "FAIL"; 
    }
    print "\n";
}

sub print_rule($$) {
    my ($name,$sub) = @_;
    print "$name: $sub\n";
}


###

sub bit_length($) {
    my ($mod) = @_;
    return length($mod) * 4; # each hex digit represents 4 bits
}

1;

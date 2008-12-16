package rules;
use cc;

#%main::rules;

#$rules{'ca'} = {   'cert'=>{},
#                    'crl'=>{},
#                    'meta'=>{}};
#$rules{'ee'} = {   'common' => {},
#                    'user' => {},
#                    'host' => {},
#                    'robot' => {}};
#
%rules = {};
$rules{'ee'}{'common'} = {
    'subject_not_null' =>
        sub() { $x509->subject() ne ""; },
    'key_length' =>
        sub() { my $len = cc::bit_length($x509->modulus());
            $len >= 2048 && $len < 10240;},
        # 'basic_constraints' =>
        #sub() { my $bc = 
    };

1;

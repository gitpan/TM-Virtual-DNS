use strict;
use warnings;

# change 'tests => 1' to 'tests => last_test_to_print';
use Test::More qw(no_plan);

use Log::Log4perl;
Log::Log4perl->init("t/log.conf");
our $log = Log::Log4perl->get_logger("TM");

use Data::Dumper;

sub _chomp {
    my $s = shift;
    chomp $s;
    return $s;
}

#== TESTS =====================================================================

use lib '../../tm_base/lib', '../tm_base/lib';

use TM::PSI;
use TM;

require_ok( 'TM::Virtual::DNS' );

{
  my $tm = new TM::Virtual::DNS;
  ok ($tm->isa ('TM::Virtual::DNS'), 'class');
  ok ($tm->isa ('TM'), 'class');
}

my $tm = new TM::Virtual::DNS (baseuri => 'dns:myhost/');

{
    my @l = $tm->mids ('localhost', '131.244.8.106', \ 'urn:x-ip:131.244.8.106', \ 'urn:x-fqdn:monad.it.bond.edu.au', 'monad.it.bond.edu.au');
# warn Dumper \@l;
    ok (eq_array (\@l,
		  [
		   'dns:myhost/localhost',
		   'dns:myhost/ip:131.244.8.106',
		   'dns:myhost/ip:131.244.8.106',
		   'dns:myhost/fqdn:monad.it.bond.edu.au',
		   'dns:myhost/fqdn:monad.it.bond.edu.au',
		   ]), 'mids');
    my @res  = $tm->midlet (@l);

# warn Dumper \@res; exit;
    ok (eq_array (\@res,
		  [
		   [ undef, ['http://topicmaps.bond.edu.au/mda/internet/dns/localhost', 'http://en.wikipedia.org/wiki/Localhost' ] ],
		   [ undef, ['urn:x-ip:131.244.8.106' ] ],
		   [ undef, ['urn:x-ip:131.244.8.106' ] ],
		   [ undef, ['urn:x-fqdn:monad.it.bond.edu.au' ] ],
		   [ undef, ['urn:x-fqdn:monad.it.bond.edu.au' ] ],
		   ]), 'all results');


    ok (eq_array ([ $tm->types ($tm->mids ('localhost')) ],
		  [ 'dns:myhost/fqdn' ]), 'type');
    ok (eq_array ([ $tm->types ($tm->mids ('monad.it.bond.edu.au')) ],
		  [ 'dns:myhost/fqdn' ]), 'type');
    ok (eq_array ([ $tm->types ($tm->mids ('131.244.8.106')) ],
		  [ 'dns:myhost/ip-address' ]), 'type');
    ok (eq_array ([ $tm->types ($tm->mids ('127.0.0.1')) ],
		  [ 'dns:myhost/ip-address' ]), 'type');
}
exit;

{ # simple name resolution
    use Test::Deep;

    cmp_deeply( [  $tm->match_forall (irole => $tm->mids ('fqdn'), iplayer => $tm->mids ('localhost'), type => $tm->mids ('lookup')) ],
		[  $tm->match_forall (irole => $tm->mids ('ip-address'), iplayer => $tm->mids ('127.0.0.1'), type => $tm->mids ('lookup')) ],
		"localhost forward/reverse" );

#   a.root-servers.net.     999     IN      A       198.41.0.4
    my @As = $tm->match_forall (irole => $tm->mids ('fqdn'), iplayer => $tm->mids ('a.root-servers.net.'), type => $tm->mids ('lookup'));

    foreach my $a (@As) {
	my $ip = TM::get_x_player ($tm, $a, $tm->mids ('ip-address') );
	$ip =~ s/[^0-9]+(\d+.*)/$1/; # throw away prefix
	ok (scalar $tm->match_forall (irole => $tm->mids ('ip-address'), iplayer => $tm->mids ($ip), type => $tm->mids ('lookup')), 'A root server reverse');
    }

    ok ($tm->match_exists (irole => $tm->mids ('fqdn'), iplayer => $tm->mids ('a.root-servers.net.'), type => $tm->mids ('lookup')), 'exists');

}


__END__

{ # simple name resolution
    use TM::QL;
    my $qq = new TM::QL ('localhost');
    my $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)), 'localhost: result one singleton');
    is ($r->[0]->[0],           'dns:myhost/localhost',   'localhost: content');

    $qq = new TM::QL ('< urn:x-ip:131.244.8.106 , urn:x-fqdn:monad.it.bond.edu.au >');
    $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 2)),     'ip: result one tuple');
    is ($r->[0]->[0],    'urn:x-ip:131.244.8.106',            'ip: content');
    is ($r->[0]->[1],    'urn:x-fqdn:monad.it.bond.edu.au',   'ip: content');
}

{ # finding the class
    use TM::QL;
    my $qq = new TM::QL ('localhost -> instance / class');
    my $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'isa: result one tuple');
    is ($r->[0]->[0],    'dns:myhost/fqdn',                   'isa: content');

    $qq = new TM::QL ('urn:x-fqdn:www.google.com -> instance / class');
    $r = $qq->eval ({'%_' => $tm});
#warn "r: ".Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'isa: result one tuple');
    is ($r->[0]->[0],    'dns:myhost/fqdn',                   'isa: content');

    $qq = new TM::QL ('urn:x-ip:131.244.8.106 -> instance / class');
    $r = $qq->eval ({'%_' => $tm});
#warn "r: ".Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'isa: result one tuple');
    is ($r->[0]->[0],    'dns:myhost/ip-address',             'isa: content');

}

{ # localhost speciality
    use TM::QL;
    my $qq = new TM::QL ('localhost -> fqdn / ip-address');
    my $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'urn:x-ip:127.0.0.1',                'lookup: content');

    $qq = new TM::QL ('urn:x-ip:127.0.0.1 -> ip-address / fqdn');
    $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'dns:myhost/localhost',              'lookup: content');

    $qq = new TM::QL ('localhost -> fqdn / ip-address -> ip-address / fqdn');
    $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'dns:myhost/localhost',              'lookup: content');
}

{ # general lookup, single
    use TM::QL;

    my $qq = new TM::QL ('urn:x-ip:131.244.8.106 -> ip-address');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'dns:myhost/60af927a961d454fccbf687cdad6042a',   'lookup: content');

    $qq = new TM::QL ('urn:x-ip:131.244.8.106 -> ip-address / fqdn');
    $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'urn:x-fqdn:monad.it.bond.edu.au',   'lookup: content');

    $qq = new TM::QL ('urn:x-fqdn:monad.it.bond.edu.au -> fqdn / ip-address');
    $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'urn:x-ip:131.244.8.106',            'lookup: content');

    $qq = new TM::QL ('urn:x-fqdn:monad.it.bond.edu.au -> fqdn / ip-address -> ip-address / fqdn');
    $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'urn:x-fqdn:monad.it.bond.edu.au',   'lookup: content');
}

{ # lookup type
    use TM::QL;

    my $qq = new TM::QL ('urn:x-ip:131.244.8.106 -> ip-address -> instance / class');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'dns:myhost/lookup',                 'lookup: content');
}

{ # lookup multiple
    use TM::QL;

    my $qq = new TM::QL ('urn:x-fqdn:www.google.com. -> fqdn');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (scalar @$r > 1,                                       'lookup: result more than one tuple');
}

{ # enumerating
    use TM::QL;

    my $qq = new TM::QL ('%_ // fqdn');
    eval {
	my $r = $qq->eval ({'%_' => $tm});
    }; like ($@, qr/unwilling/, _chomp $@);
    $qq = new TM::QL ('%_ // ip-address');
    eval {
	my $r = $qq->eval ({'%_' => $tm});
    }; like ($@, qr/unwilling/, _chomp $@);

}

__END__

{ # embedding it into the TM architecture
    use TM;
    $TM::schemes{'dns:.*'} = 'TM::Virtual::DNS';
    my $tm = new TM ('> dns:localhost: >');

#    warn Dumper $tm;

    my @l = $tm->mids ('localhost', 'urn:x-ip:131.244.8.106', 'urn:x-fqdn:monad.it.bond.edu.au', 'rumsti');
    ok (eq_array (\@l,
		  [
		   'dns:localhost:localhost',
		   'urn:x-ip:131.244.8.106',
		   'urn:x-fqdn:monad.it.bond.edu.au',
		   undef
		   ]), 'mids via TM');

    use TM::QL;
    my $qq = new TM::QL ('urn:x-ip:131.244.8.106 -> ip-address / fqdn');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),                    'via TM: lookup: result one tuple');
    is ($r->[0]->[0],    'urn:x-fqdn:monad.it.bond.edu.au',                  'via TM: lookup: content');
}

__END__



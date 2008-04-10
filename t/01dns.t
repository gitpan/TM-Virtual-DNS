use strict;
use warnings;

# change 'tests => 1' to 'tests => last_test_to_print';
use Test::More qw(no_plan);

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

{
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');
    is ( $tm->tids ('localhost'), 'dns:localhost', 'localhost');

    ok (eq_array ([ $tm->toplet ($tm->tids ('localhost')) ],
		  [
		   [ $tm->tids ('localhost'), 
		     undef,
		     ['http://topicmaps.bond.edu.au/mda/internet/dns/localhost', 'http://en.wikipedia.org/wiki/Localhost' ] 
		     ],
		   ]), 'localhost structure');
    ok (eq_array ([ $tm->types ($tm->tids ('localhost')) ],
		  [ 'dns:fqdn' ]),                 'localhost type');
    ok (eq_array ([ $tm->types ($tm->tids ('127.0.0.1')) ],
		  [ 'dns:ip-address' ]), 'type');
}

use constant HOST => 'dns1.arcs.ac.at';
use constant IP   => '62.218.164.160';

{ # toplet construction, types
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    my @l = $tm->tids (IP, \ ('urn:x-ip:'.IP), \ ('urn:x-fqdn:'.HOST), HOST);
#warn Dumper \@l;
    ok (eq_array (\@l,
		  [
		   'dns:ip:'  .IP,
		   'dns:ip:'  .IP,
		   'dns:fqdn:'.HOST,
		   'dns:fqdn:'.HOST,
		   ]), 'tids');


    my @res  = $tm->toplets (@l);

#warn Dumper \@res;
    ok (eq_array (\@res,
		  [
		   [ 'dns:ip:'  .IP,   undef, ['urn:x-ip:'.IP ] ],
		   [ 'dns:ip:'  .IP,   undef, ['urn:x-ip:'.IP ] ],
		   [ 'dns:fqdn:'.HOST, undef, ['urn:x-fqdn:'.HOST ] ],
		   [ 'dns:fqdn:'.HOST, undef, ['urn:x-fqdn:'.HOST ] ],
		   ]), 'all results');

    ok (eq_array ([ $tm->types ($tm->tids (HOST)) ],
		  [ 'dns:fqdn' ]), 'type');
    ok (eq_array ([ $tm->types ($tm->tids (IP)) ],
		  [ 'dns:ip-address' ]), 'type');
}

{ # simple name resolution
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use Test::Deep;
    cmp_deeply( [  $tm->match_forall (irole => $tm->tids ('fqdn'),       iplayer => $tm->tids ('localhost'), type => $tm->tids ('lookup')) ],
		[  $tm->match_forall (irole => $tm->tids ('ip-address'), iplayer => $tm->tids ('127.0.0.1'), type => $tm->tids ('lookup')) ],
		"localhost forward/reverse" );

    ok ($tm->match_exists (irole => $tm->tids ('fqdn'), iplayer => $tm->tids ('a.root-servers.net.'), type => $tm->tids ('lookup')), 'exists');

#   a.root-servers.net.     999     IN      A       198.41.0.4
    my @As = $tm->match_forall (irole => $tm->tids ('fqdn'), iplayer => $tm->tids ('a.root-servers.net.'), type => $tm->tids ('lookup'));

    foreach my $a (@As) {
	my ($ip) = TM::get_x_players ($tm, $a, $tm->tids ('ip-address') );
	$ip =~ s/[^0-9]+(\d+.*)/$1/; # throw away prefix
	ok (scalar $tm->match_forall (irole => $tm->tids ('ip-address'), iplayer => $tm->tids ($ip), type => $tm->tids ('lookup')), 'A root server reverse');
    }
}

{ # simple name resolution, TMQL
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use TM::QL;
    my $qq = new TM::QL ('localhost');
    my $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)), 'localhost: result one singleton');
    is ($r->[0]->[0],           'dns:localhost',          'localhost: content');

    $qq = new TM::QL ('urn:x-ip:'.IP);
    $r = $qq->eval ({'%_' => $tm});
warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)), 'ip: result one tuple');
    is ($r->[0]->[0],    'dns:ip:'.IP,                    'ip: content');

    $qq = new TM::QL ('( urn:x-ip:'.IP.' , urn:x-fqdn:'.HOST.' )');
    $r = $qq->eval ({'%_' => $tm});
warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 2)), 'ip: result one tuple');
    is ($r->[0]->[0],    'dns:ip:'.IP,                    'ip: content');
    is ($r->[0]->[1],    'dns:fqdn:'.HOST,                'ip: content');
}

{ # finding the class
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use TM::QL;
    my $qq = new TM::QL ('localhost <- instance -> class');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'isa: result one tuple');
    is ($r->[0]->[0],    'dns:fqdn',                          'isa: content');

    $qq = new TM::QL ('urn:x-fqdn:www.google.com <- instance -> class');
    $r = $qq->eval ({'%_' => $tm});
#warn "r: ".Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'isa: result one tuple');
    is ($r->[0]->[0],    'dns:fqdn',                          'isa: content');

    $qq = new TM::QL ('urn:x-ip:'.IP.' <- instance -> class');
    $r = $qq->eval ({'%_' => $tm});
#warn "r: ".Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'isa: result one tuple');
    is ($r->[0]->[0],    'dns:ip-address',                    'isa: content');

}

{ # localhost speciality
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use TM::QL;
    my $qq = new TM::QL ('localhost <- fqdn -> ip-address');
    my $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'dns:ip:127.0.0.1',                  'lookup: content');

    $qq = new TM::QL ('urn:x-ip:127.0.0.1 <- ip-address -> fqdn');
    $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'dns:localhost',                     'lookup: content');

    $qq = new TM::QL ('localhost <- fqdn -> ip-address <- ip-address -> fqdn');
    $r = $qq->eval ({'%_' => $tm});
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),     'lookup: result one tuple');
    is ($r->[0]->[0],    'dns:localhost',                     'lookup: content');
}

{ # general lookup, single
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use TM::QL;

    my $qq = new TM::QL ('urn:x-ip:'.IP.' <- ip-address');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),         'general lookup: result one tuple');
    is ($r->[0]->[0],    'f55f7d4b64cfefb09fb3ec7f57607cb1',      'general lookup: content');

    $qq = new TM::QL ('urn:x-ip:'.IP.' <- ip-address -> fqdn');
    $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),         'general lookup: result one tuple');
    is ($r->[0]->[0],    'dns:fqdn:'.HOST,                        'general lookup: content');

    $qq = new TM::QL ('urn:x-fqdn:'.HOST.' <- fqdn -> ip-address');
    $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),         'general lookup: result one tuple');
    is ($r->[0]->[0],    'dns:ip:'.IP,                            'general lookup: content');

    $qq = new TM::QL ('urn:x-fqdn:'.HOST.' <- fqdn -> ip-address <- ip-address -> fqdn');
    $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),         'general lookup: result one tuple');
    is ($r->[0]->[0],    'dns:fqdn:'.HOST,                        'general lookup: content');
}

{ # lookup type
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use TM::QL;
    my $qq = new TM::QL ('urn:x-ip:'.IP.' <- ip-address >> classes');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),         'type lookup: result one tuple');
    is ($r->[0]->[0],    'dns:lookup',                            'type lookup: content');
}

{ # lookup multiple
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use TM::QL;
    my $qq = new TM::QL ('urn:x-fqdn:www.google.com. <- fqdn');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (scalar @$r > 1,                                           'google lookup: result more than one tuple');
}

{ # enumerating
    my $tm = new TM::Virtual::DNS (baseuri => 'dns:');

    use TM::QL;
    my $qq = new TM::QL ('%_ // fqdn');
    eval {
	my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
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

    my @l = $tm->tids ('localhost', 'urn:x-ip:131.244.8.106', 'urn:x-fqdn:monad.it.bond.edu.au', 'rumsti');
    ok (eq_array (\@l,
		  [
		   'dns:localhost:localhost',
		   'urn:x-ip:131.244.8.106',
		   'urn:x-fqdn:monad.it.bond.edu.au',
		   undef
		   ]), 'tids via TM');

    use TM::QL;
    my $qq = new TM::QL ('urn:x-ip:131.244.8.106 -> ip-address / fqdn');
    my $r = $qq->eval ({'%_' => $tm});
#warn Dumper $r;
    ok (((scalar @$r == 1) and (scalar @{$r->[0]} == 1)),                    'via TM: lookup: result one tuple');
    is ($r->[0]->[0],    'urn:x-fqdn:monad.it.bond.edu.au',                  'via TM: lookup: content');
}

__END__


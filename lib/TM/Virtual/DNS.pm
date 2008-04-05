package TM::Virtual::DNS;

use TM;
use base qw(TM);

use TM::Literal;
use Data::Dumper;

# create a resolver, we need it at every lookup
use Net::DNS;
my $res = Net::DNS::Resolver->new;
$res->tcp_timeout(10);                    # 10 secs should be enough?

=pod

=head1 NAME

TM::Virtual::DNS - Virtual Topic Map for DNS retrieval

=head1 SYNOPSIS

  # standalone
  use TM::Virtual::DNS;
  my $dns = new TM::Virtual::DNS;

  # forward lookup
  my @As = $tm->match_forall (irole   => $tm->tids ('fqdn'), 
                              iplayer => $tm->tids ('a.root-servers.net.'),
                              type    => $tm->tids ('lookup'));
  print map { TM::get_x_players ($dns, $_, $dns->tids ('ip-address') } @As;

  # reverse lookup
  my @PTRs = $tm->match_forall (irole   => $tm->tids ('ip-address'), 
                                iplayer => $tm->tids ('127.0.0.1'),
                                type    => $tm->tids ('lookup'));

=head1 ABSTRACT

This class provides applications with a topicmapp-ish view of DNS, the domain name service. In this
sense the topic map is I<virtual>.

=head1 DESCRIPTION

This package overloads central methods of the L<TM> class.  In that, it provides access to DNS
information via the Topic Map paradigm according to the DNS ontology.

=head2 Ontology

While the map in its core functionality is virtual, it still is based on some fixed concepts, such
as I<IP address> or I<host name>. These are defined in the ontology which is represented textually
(in AsTMa= representation) within the string C<$ontology>.

Whenever a DNS topic map is created also this ontology is integrated, so that for the outside user
there is no visible distinction between topics declared in the ontology and topics (and
associations) created on-the-fly.

If you ever need the ontology, you can simply output it like so:

  perl -MTM::Virtual::DNS -e 'print $TM::Virtual::DNS::ontology;'

=cut

our $ontology = q{

ip-address # is-subclass-of address
bn: IP Address
sin: http://topicmaps.bond.edu.au/mda/internet/dns/ip-address
sin: http://en.wikipedia.org/wiki/IP_Address
in (urn-namespace): urn:x-ip

(is-subclass-of)
superclass: address
subclass: ip-address

fqdn # is-subclass-of name
bn: Fully Qualified Domain Name
sin: http://topicmaps.bond.edu.au/mda/internet/dns/full-qualified-domain-name
sin: http://en.wikipedia.org/wiki/Fqdn
in (urn-namespace): urn:x-fqdn

(is-subclass-of)
superclass: name
subclass:   fqdn

localhost (fqdn) # is this actually correct?
bn: localhost
sin: http://topicmaps.bond.edu.au/mda/internet/dns/localhost
sin: http://en.wikipedia.org/wiki/Localhost

lookup

# constraints do not exist at the moment

};

=pod

=head2 Identification

While the predefined concepts have subject indicators, we introduce here our own URI namespaces to
provide for subject indicators for IP addresses and FQDN:

=head3 Subject Identifiers

=over

=item C<urn:x-ip> for IP addresses

Example:

     urn:x-ip:1.2.3.4

=item C<urn:x-dns> for DNS names

Example:

     urn:x-fqdn:www.google.com

=back

This package recognizes these subject indicators:

   print "yes" if $tm->tids (\ 'urn:x-ip:123.123.123.123');

=head3 Subject Locators

There are no subject locators for IP addresses and FQDNs.

=head3 Local Identifiers

As local identifiers you can use IP addresses and FQDNs directly, they will be detected by
their syntactic structure:

   warn $tm->tids ('123.123.123.123');  # will create an absolutized local URI

   warn $tm->tids ('www.google.com');   # ditto


=head1 INTERFACE

=head2 Constructor

The constructor needs no arguments and instantiates a virtual map hovering over the DNS. For this
purpose the constructor also loads the background ontology (there is only a minimal overhead
involved with this). If you want to use a different one, it has to be replaced B<before> the
instantiation.

Example:

    my $dns = new TM::Virtual::DNS;

The following options are currently recognized:

=over

=item C<baseuri> (default: C<dns:localhost:>)

All local IDs in the virtual map will be prefixed with that baseuri.

=item C<nameservers> (default: whatever the local installation uses by default)

If this list reference is provided, the IP addresses in there will be used for name resolution.

B<Warning>: This feature cannot be tested properly automatically as many firewall setups prohibit
direct DNS access.

Example:

    my $dns = new TM::Virtual::DNS (nameservers => [ 1.2.3.4 ]);

=back

=cut

sub new {
    my $class   = shift;
    my %options = @_;
    $options{baseuri} ||= 'dns:localhost:';

    $res = Net::DNS::Resolver->new (nameservers => $options{nameservers})  # use explicit ones
	if $options{nameservers};                                          # if such an option existed

    my $self = bless $class->SUPER::new (%options), $class;

    use TM::Materialized::AsTMa;
    my $o = new TM::Materialized::AsTMa (inline  => $ontology,
					 baseuri => $self->{baseuri});
    $o->sync_in;                                                           # really load the ontology
    $self->melt ($o);                                                      # glue it to the map
    return $self;
}

=pod

=head2 Methods

This subclass of L<TM> overrides the following methods:

=over

=item B<midlets>

This method would list B<all> items in the DNS. Of course, this will not be possible, so this method
will raise an exception.

=cut

sub midlets {
    die scalar __PACKAGE__ . ": unwilling to enumerate everything in the DNS";
}

=pod

=item B<tids>

This method expects a list of I<identification> parameters and will return a fully absolutized URI
for each of these. Apart from understanding the identifiers (as explained above), it should follow
the semantics of the mother class. It can also be used in list context.

=cut

sub tids {
    my $self = shift;
    my $bu   = $self->baseuri;

#warn "tids ".Dumper \@_;

    my @ks;
    foreach (@_) {
	if (!defined $_) {
	    return undef;
	} elsif (ref ($_)) {                                             # we got a subject indicator
	    my $si = $$_;
	    if ($si =~ /^urn:x-ip:((\d+)\.(\d+)\.(\d+)\.(\d+))$/ &&      # that indicating an IP address
		$2 < 256 && $3 < 256 && $4 < 256 && $5 < 256) {
		push @ks, $bu.'ip:'.$1;

	    } elsif ($si =~ /^urn:x-fqdn:([\w\-\.]+)$/ ) {               # that indicating a FQDN
		push @ks, $bu.'fqdn:'.$1;

	    } else {
		push @ks, $self->SUPER::tids ($_);
	    }

	# } elsif () {                                                   # in this world we NEVER have a subject locator

	} elsif ($self->{mid2iid}->{$_}) {                               # we got an absolute one
	    push @ks, $_;                                                # take that and run

	} elsif ($self->{mid2iid}->{$bu.$_}) {                           # simply prepending baseuri helps
	    push @ks, $bu.$_;                                            # take it

	} elsif (/^((\d+)\.(\d+)\.(\d+)\.(\d+))$/ &&                     # looks and
		 $2 < 256 && $3 < 256 && $4 < 256 && $5 < 256) {         # smells like an IP address
	    push @ks, $bu.'ip:'.$_;                                      # go with it

	} elsif (/^[\w\-\.]+$/ ) {                                       # cheapskate match for a name
	    push @ks, $bu.'fqdn:'.$_,                                    # take that

	} else {                                                         # do not know what it should be
	    push @ks, undef;
	}
    }
#warn "tids end ".Dumper \@ks;
    return wantarray ? @ks : $ks[0];
}

=pod

=item B<toplets>

This method returns toplet structures as described in L<TM>, either those of predefined concepts or
ones which are created on the fly if we are dealing with IP addresses or FQDNs.

=cut

sub toplets {
    my $self = shift;
    my $bu   = $self->baseuri;

    $TM::log->logdie (scalar __PACKAGE__ . ": unwilling to enumerate everything") unless @_;

    my @ks   = map {
	            $self->tids ($_) 
                    ? $self->SUPER::toplets ($_)                       # if it is in the background map, then let's take that
                    : ( ( /^${bu}ip:(.+)$/ )                           # smells like an IP address
		      ? [ $_, undef, [ 'urn:x-ip:'.$1 ] ]              # create a toplet with subject indicator on the fly
		      : ( /^${bu}fqdn:([\w\-\.]+)$/                    # smells like a name
		        ? [ $_, undef, [ 'urn:x-fqdn:'.$1 ] ]          # create toplet with subject indicator in the fly
		        : undef                                        # no idea what this should be
		        )
		      )
		} @_;

    return wantarray ? @ks : $ks[0];
}

=pod

=item B<match_forall>

@@@@ doc!! @@@

@@@ which axes are supported @@@

=cut

sub _match_forall {
    my @x = _match_forall (@_);
    warn "returning form DNS match ".Dumper \@x;
    return @x;
}

sub match_forall {
    my $self   = shift;
    my $bu     = $self->baseuri;
    my %query  = @_;
#warn "# dns match!!!" .Dumper \%query;

    $TM::log->logdie (scalar __PACKAGE__ . ": unwilling to enumerate everything") unless %query;

    my ($LOOKUP, $FQDN, $IP_ADDRESS, $INSTANCE, $CLASS) = $self->tids ('lookup', 'fqdn', 'ip-address', 'instance', 'class');

    if ($query{char}) {                                                   # want characteristics of something
	$_ = $query{irole};

	if (/ip:(.*)/) {                                                  # 123.123.123.123
	    return $self->assert (
				  [ undef,
				    undef,
				    'name',
				    TM->NAME,
				    [ 'thing', 'value' ],
				    [ $_,      new TM::Literal ("$1") ],
				    ]);

	} elsif (/fqdn:(.+)$/ ) {                                         # www.rumsti.ramsti.de
	    return $self->assert (
				  [ undef,
				    undef,
				    'name',
				    TM->NAME,
				    [ 'thing', 'value' ],
				    [ $_,      new TM::Literal ("$1") ],
				    ]);

	} else {
	    return $self->SUPER::match_forall (%query);
	}
    } elsif ($query{instance} ||                                          # either we directly ask for instance assocs
             (defined $query{irole} &&
               $query{irole} eq $INSTANCE &&                              # or we have the role instance 
              ($query{instance} = $query{iplayer}))) {                    # and the player has the instance
	if ($query{instance} eq $bu.'localhost' ||
	    $query{instance} =~ /fqdn:(.+)$/) {
	    return $self->assert (Assertion->new (scope   => 'us',
						  type    => 'isa',
						  roles   => [ 'class', 'instance' ],
						  players => [ 'fqdn',  $query{instance} ]));

	} elsif ($query{instance} =~ /ip:(.+)/) {
	    return $self->assert (Assertion->new (scope   => 'us',
						  type    => 'isa',
						  roles   => [ 'class',     'instance' ],
						  players => [ 'ip-address', $query{instance} ]));

	} else {
	    return $self->SUPER::match_forall (@_);
	}


    } elsif ($query{irole} && $query{iplayer}) {
                      # actually we do not look at the type here
                      # TODO: maybe we should
	if (($query{irole} eq $FQDN       && $query{iplayer} eq $bu.'localhost') ||
	    ($query{irole} eq $IP_ADDRESS && $query{iplayer} eq $bu.'ip:127.0.0.1')) {
	    return $self->assert (Assertion->new (scope   => 'us',
						  type    => 'lookup',
						  roles   => [ 'fqdn',      'ip-address' ],
						  players => [ 'localhost', '127.0.0.1' ]));

	} elsif ($query{irole} eq $FQDN        && $query{iplayer} =~ /fqdn:(.+)/) {
	    my $host = $1;
	    my @a_records;
	    if (my $query = $res->search($host)) {
		foreach my $rr ($query->answer) {
		    next unless $rr->type eq "A";
		    push @a_records, $self->assert (Assertion->new (scope   => 'us',
								    type    => 'lookup',
								    roles   => [ 'fqdn',          'ip-address' ],
								    players => [ $query{iplayer},  $rr->address ]));
		}
	    }
	    return @a_records;

	} elsif ($query{irole} eq $IP_ADDRESS     && $query{iplayer} =~ /ip:(.+)/) {
	    my $ip = $1;
	    my @a_records;
	    if (my $query = $res->search($ip)) {
		foreach my $rr ($query->answer) {
		    next unless $rr->type eq "PTR";
		    push @a_records, $self->assert (Assertion->new (scope   => 'us',
								    type    => 'lookup',
								    roles   => [ 'fqdn',        'ip-address' ],
								    players => [ $rr->ptrdname, $query{iplayer} ]));
		}
	    }
	    return @a_records;
	} else {
	    return ();  # absolutely nothing else served here
	}

    } else {
	return $self->SUPER::match_forall (@_);
    }
}


=pod

=item B<match_exists>

See C<match_forall>.

=cut

# cheapskate solution
sub match_exists {
    my $self = shift;
    return 1 if $self->match_forall (@_);
}

=pod

=back

=head1 SEE ALSO

L<TM>

=head1 AUTHOR

Robert Barta, E<lt>drrho@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 200[3568] by Robert Barta

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

our $VERSION  = '0.11';
our $REVISION = '$Id: DNS.pm,v 1.8 2006/12/11 10:23:55 rho Exp $';

1;

__END__

 =item B<toplets>

I<@toplets> = I<$tm>->toplets (I<@list_of_tids>)

This method implements the abstract one given in L<TM::Retrieve>.  It
(dynamically) generates toplets based on the provided (list of) topic
identifier(s).

You can try to omit the parameters, but then you will force the
package to give you all things it finds in the DNS. Not likely to
happen :-)

# TODO: Maybe later.

Examples:

   $localhost = $tm->toplets  ('localhost');
   $google    = $tm->toplets  ('urn:x-fqdn:www.google.com');
   $firewall  = $tm->toplets  ('urn:x-ip:192.168.0.1');

 =cut

sub xxxxxxxxtoplets {
  my $self = shift;
  return $self->{store}->toplets (@_);
}

 =pod



 =item B<maplets>

I<@maplets> = I<$tm>->maplets (I<$template>)

This method implements that described in L<TM::Access>. It dynamically
generates maplets according to the template passed in. It returns a
list of maplets matching the template search specification. It
supports only the following templates:

  TemplateFTypeFMember

Otherwise an exception is raised. If a search would result in a long
list, the method will raise an exception.

 =cut

sub xxxxxxxxxxxxxxxmaplets  {
  my $self     = shift;
  my $template = shift;

  my $ref_template = ref ($template);

##warn "dns maplet, resolving ".Dumper $template;

  if ($ref_template eq 'TemplateWildcard') {
    die "unwilling to enumerated all maplets";
  } elsif ($ref_template eq 'TemplateIPlayer') {       return _make_isa_s      ($template->iplayer),
							      _make_instance_s ($template->iplayer),
							      _make_forward_s  ($template->iplayer),
							      _make_reverse_s  ($template->iplayer);

  } elsif ($ref_template eq 'TemplateIPlayerIRole') {
    if ($template->irole eq 'fqdn') {                  return _make_forward_s  ($template->iplayer);
    } elsif ($template->irole eq 'ip-address') {       return _make_reverse_s  ($template->iplayer);
    } elsif ($template->irole eq 'class') {            return _make_instance_s ($template->iplayer);
    } elsif ($template->irole eq 'instance') {         return _make_isa_s      ($template->iplayer);
    } else { # ignore all others
    }

  } elsif ($ref_template eq 'TemplateIPlayerType') {
    if ($template->type eq 'is-a') {                   return _make_isa_s      ($template->iplayer),
							      _make_instance_s ($template->iplayer);
    } elsif ($template->type eq 'has-lookup') {        return _make_forward_s  ($template->iplayer),
							      _make_reverse_s  ($template->iplayer);
    } else { # ignore
    }

  } elsif ($ref_template eq 'TemplateIPlayerIRoleType') {
    if ($template->type eq 'is-a' &&
        $template->irole eq 'class') {                 return _make_instance_s ($template->iplayer);
    } elsif ($template->type eq 'is-a' &&
             $template->irole eq 'instance') {         return _make_isa_s      ($template->iplayer);
    } elsif ($template->type eq 'has-lookup' &&
	     $template->irole eq 'fqdn') {             return _make_forward_s  ($template->iplayer);
    } elsif ($template->type eq 'has-lookup' &&
	     $template->irole eq 'ip-address') {       return _make_reverse_s  ($template->iplayer);
    } else {
      # ignore
    }

##  } elsif ($ref_template eq 'Maplet') {
  } else {
    die "template '$ref_template' not implemented";
  }
}

 sub _make_isa_s {
  my $tid = shift;

  if ($tid eq 'localhost') {
    return (new Maplet (scope   => $TM::PSI::US,
			type    => 'is-a',
			roles   => [ 'instance',  'class' ],
			players => [ $tid,        'fqdn' ]));

  } elsif ($tid =~ /^ip-((\d+)-(\d+)-(\d+)-(\d+))$/) {
    return (new Maplet (scope   => $TM::PSI::US,
			type    => 'is-a',
			roles   => [ 'instance',  'class' ],
			players => [ $tid,        'ip-address' ]));

  } elsif ($tid =~ /^([\w-]+)$/) {
    return (new Maplet (scope   => $TM::PSI::US,
			type    => 'is-a',
			roles   => [ 'instance',  'class' ],
			players => [ $tid,        'fqdn' ]));
  } else {
    return (); # not known -> so no assoc
  }
}

sub _make_instance_s {
  my $tid = shift;

  if ($tid eq 'fqdn') {
    die "unwilling to enumerate instances";
  } elsif ($tid eq 'ip-address') {
    die "unwilling to enumerate instances";
  } else {
    return ();
  }
}

 =pod


      } elsif ($_ =~ /^((\d+)\.(\d+)\.(\d+)\.(\d+))$/ &&
	       $2 < 256 && $3 < 256 && $4 < 256 && $5 < 256) {
	  push @l, new Toplet (lid   => $self->{baseuri}.ip2tid ($_),
			       sids  => [ "urn:x-ip:$1" ],
			       chars => [ new Characteristic (lid   => undef,
							      scope => $self->{ontology}->tids ('us'),
							      type  => $self->{ontology}->tids ('has-basename'),
							      kind  => TM::Retrieve::KIND_BN, 
							      value => $1 ) ]);
	  
      } elsif ($_ =~ /^ip-((\d+)-(\d+)-(\d+)-(\d+))$/ &&
	       $2 < 256 && $3 < 256 && $4 < 256 && $5 < 256) {
	  push @l, new Toplet (lid   => $self->{baseuri}.$_,
			       sids  => [ "urn:x-ip:$2.$3.$4.$5" ],
			       chars => [ new Characteristic (lid   => undef,
							      scope => $self->{ontology}->tids ('us'),
							      type  => $self->{ontology}->tids ('has-basename'),
							      kind  => TM::Retrieve::KIND_BN, 
							      value => "$2.$3.$4.$5" ) ]);

      } elsif ($_ =~ /^(.*?\.[\w-]+\.[\w-]+)$/ ) {  # www.rumsti-ramsti.de
	  push @l, new Toplet (lid   => $self->{baseuri}.host2tid ($_),
			       sids  => [ "urn:x-dns:$_" ],
			       chars => [ new Characteristic (lid   => undef,
							      scope => $self->{ontology}->tids ('us'),
							      type  => $self->{ontology}->tids ('has-basename'),
							      kind  => TM::Retrieve::KIND_BN, 
							      value => $1 ) ]);

      } elsif ($_ =~ /^([\w-]+)$/ ) {               # www-rumsti--ramsti-de
	  push @l, new Toplet (lid   => $self->{baseuri}.$_,
			       sids  => [ "urn:x-dns:".tid2host ($_) ],
			       chars => [ new Characteristic (lid   => undef,
							      scope => $self->{ontology}->tids ('us'),
							      type  => $self->{ontology}->tids ('has-basename'),
							      kind  => TM::Retrieve::KIND_BN, 
							      value => tid2host ($_) ) ]);

      } else {                                                        # whatta crap is that?
	  push @l, undef;
      }


sub ip2tid {
  my $tid = shift;
  $tid =~ s/\./\-/g;
  return "ip-$tid";
}

sub tid2ip {
  my $tid = shift;
  my ($ip) = $tid =~ /^ip-(.+)/;
  $ip =~ s/-/./g;
  return $ip;
}

sub host2tid {
  my $x = shift;
  $x =~ s/-/--/g;
  $x =~ s/\./\-/g;
  return $x;
}

sub tid2host {
  my $x = shift;
  $x =~ s/-(?!-)/./g;
  $x =~ s/--/-/g;
  return $x;
}



__END__

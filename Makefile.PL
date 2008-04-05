use 5.008001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'TM::Virtual::DNS',
    VERSION_FROM      => 'lib/TM/Virtual/DNS.pm', # finds $VERSION
    PREREQ_PM         => {
	'TM'          => 1.33,
	'Net::DNS'    => 0.19,
	"Test::More"  => 0.47,
	"Test::Pod"   =>  1.00,
	"Log::Log4perl"  => 0.50,
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/TM/Virtual/DNS.pm', # retrieve abstract from module
       AUTHOR         => 'Robert Barta <drrho@cpan.org>') : ()),
);

package MY;

sub depend {
    return <<MAKE

dependencies:
	scandeps.pl `grep .pm MANIFEST` `grep bin/ MANIFEST`| grep -v undef

manifesto:
	find lib/ -iname '*.pm' | sort
	find t    -iname '*.t'  | sort

upload:
	cpan-upload-http TM-Virtual-DNS-\$(VERSION).tar.gz

inject:
	mcpani --add --module TM::Virtual::DNS --authorid DRRHO --modversion \$(VERSION) --file TM-Virtual-DNS-\$(VERSION).tar.gz
	sudo mcpani --inject
	echo "reload index" | cpan

debian:
	(cd /usr/local/share/packages; rm -rf TM-Virtual-DNS* ; dh-make-perl --cpan-mirror file:/usr/local/share/minicpan --build --cpan TM::Virtual::DNS --notest)

MAKE
}

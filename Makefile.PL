use 5.008001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'TM::Virtual::DNS',
    VERSION_FROM      => 'lib/TM/Virtual/DNS.pm', # finds $VERSION
    PREREQ_PM         => {
	'TM'          => 1.23,
	'Net::DNS'    => 0.19,
	'Test::Deep'  => 0.093,
	"Test::More"  => 0.47,
	"Test::Pod"   =>  1.00,
	"Log::Log4perl"  => 0.50,
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/TM/Virtual/DNS.pm', # retrieve abstract from module
       AUTHOR         => 'Robert Barta <drrho@cpan.org>') : ()),
);

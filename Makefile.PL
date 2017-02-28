use ExtUtils::MakeMaker;

use Apache::TestMM;

#use lib qw(../blib/lib lib);

my %require => {
    "Apache::Test" => 0,
};

my @scripts = qw(t/TEST);
print STDOUT %scripts;

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteMakefile(
    NAME => 'Apache::Test_mod_perimeterx',
    PREREQ_PM => \%require,
    clean => {
        FILES => "@{ clean_files() }",
    },
);

sub clean_files {
    return [@scripts];
}


#!/usr/bin/perl -w

use strict;

my $i;
my $m;

print "/* This file was automatically generated */\n";
print "#include <mrd/mrd.h>\n";

for ($i = 0; $i <= $#ARGV; $i++) {
	$m = lc $ARGV[$i];
	print "extern \"C\" mrd_module *mrd_module_init_$m(void *, mrd *);\n";
}

print "void mrd::add_static_modules() {\n";
for ($i = 0; $i <= $#ARGV; $i++) {
	$m = lc $ARGV[$i];
	print "\tm_static_modules[\"$m\"] = &mrd_module_init_$m;\n";
}
print "}\n";

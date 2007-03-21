#!/usr/bin/perl

use strict;

my $enable_modules = 1;
my $use_opts = 0;
my $use_space_opts = 0;
my $prefix = '/usr/local';

my @mrd_modules = (
	'mld', 'pim', 'console', 'bgp', 'msnip', 'mrdisc', 'ripng'
);

my @modules = (
	@mrd_modules, 'linux', 'support'
);

my %mrd_modules_desc = (
	'mld' => 'Multicast Listener Discovery v1/v2 (MLD)',
	'pim' => 'Protocol Independent Multicast Sparse Mode (PIM-SM)',
	'console' => 'Interactive configuration',
	'bgp' => 'Border Gateway Protocol with Multicast SAFI (BGP4+)',
	'msnip' => 'Multicast Source Notification of Interest Protocol',
	'mrdisc' => 'Multicast Router Discovery'
);

my %static_modules = (
	'mld'		=> 1,
	'pim'		=> 1,
	'console'	=> 1,
	'bgp'		=> 0,
	'msnip'		=> 0,
	'mrdisc'	=> 0
);

my %external_modules = (
	'mld'		=> 0,
	'pim'		=> 0,
	'console'	=> 0,
	'bgp'		=> 1,
	'msnip'		=> 1,
	'mrdisc'	=> 1
);

my @adv_options = (
	'NO_INLINE'
);

my %adv_options_desc = (
	'NO_INLINE'		=> 'Don\'t inline methods, easier debugging'
);

my %adv_options_values = (
	'NO_INLINE'		=> 0
);

use constant FIRST_MENU		=> 0;
use constant STATIC_MODULE_MENU	=> 1;
use constant DYN_MODULE_MENU	=> 2;
use constant ASK_WRITE_CONFIG	=> 3;
use constant ADVANCED_MENU	=> 4;
use constant MODULE_OPTIONS_MENU=> 5;

my $state = FIRST_MENU;

my $menu_result;

my %module_options = ();

my $dialog = 'dialog';

sub check_dialog {
	my $res = system("$dialog --version") or 1;

	if ($res ne 0) {
		print "dialog(1) or compatible is required to run the configuration.\n";
		exit 1;
	}
}

sub run_menu {
	my ($command) = @_;
	my $res = 1;

	pipe(READER, WRITER);

	my $pid = fork;

	if ($pid == 0) {
		close(READER);
		open(STDERR, ">&WRITER");
		exec($command);
	}

	if ($pid > 0) {
		close(WRITER);
		$menu_result = <READER>;
		close(READER);
		waitpid($pid, 0);
		$res = $?;
	}

	return $res;
}

sub _build_modlist {
	my ($input) = @_;
	my $res = '"';

	foreach (@mrd_modules) {
		if ($input->{$_}) {
			$res .= ', ' if $res ne '"';
			$res .= $_;
		}
	}

	if ($res eq '"') {
		$res .= '<None>';
	}

	return $res . '"';
}

sub _boolean_entry {
	my ($name, $val) = @_;
	my $res = ' "' . $name . '" ';

	if ($val) {
		$res .= '"Enabled"';
	} else {
		$res .= '"Disabled"';
	}
}

sub _is_module_enabled {
	my $name = shift;

	return 1 if $name eq 'linux' or $name eq 'support';

	return $static_modules{$name} or $external_modules{$name};
}

my $choose_msg = 'Choose one of the available options';

sub first_menu {
	my $command = "$dialog --title \"MRD6 Configuration\" --no-cancel --menu \"$choose_msg\" 0 0 0";
	my $res;

	$command .= ' "Exit Configuration" ""';
	$command .= _boolean_entry('Module Loading Support', $enable_modules);
	$command .= _boolean_entry('Optimizations', $use_opts);
	$command .= _boolean_entry('Space Optimizations', $use_space_opts) if $use_opts;
	$command .= " \"Installation Prefix\" \"$prefix\"";
	$command .= ' "Included modules" ' . _build_modlist(\%static_modules);
	$command .= ' "External modules" ' . _build_modlist(\%external_modules) if $enable_modules;

	foreach (@modules) {
		if (_is_module_enabled $_) {
			my $ref = $module_options{$_};

			if (scalar keys %$ref > 0) {
				$command .= ' "' . (uc $_) . ' Module Options -->" ""';
			}
		}
	}

	$command .= ' "Advanced Options -->" ""';

	$res = run_menu $command;

	if ($menu_result eq 'Exit Configuration') {
		$state = ASK_WRITE_CONFIG;
	} elsif ($menu_result eq 'Module Loading Support') {
		$enable_modules = !$enable_modules;
	} elsif ($menu_result eq 'Optimizations') {
		$use_opts = !$use_opts;
	} elsif ($menu_result eq 'Space Optimizations') {
		$use_space_opts = !$use_space_opts;
	} elsif ($menu_result eq 'Installation Prefix') {
	} elsif ($menu_result eq 'Included modules') {
		$state = STATIC_MODULE_MENU;
	} elsif ($menu_result eq 'External modules') {
		$state = DYN_MODULE_MENU;
	} elsif ($menu_result eq 'Advanced Options -->') {
		$state = ADVANCED_MENU;
	} else {
		$menu_result =~ s/^([A-Z]+) Module Options -->$/$1/;
		$menu_result = lc $menu_result;
		$state = MODULE_OPTIONS_MENU;
	}
}

my $pretty_msg = "Select from the available module list";

sub module_menu {
	my ($input) = @_;
	my $res;

	my $command = "$dialog --single-quoted --checklist \"$pretty_msg\" 0 0 0";

	foreach (@mrd_modules) {
		$command .= ' "' . $_ . '" "' . $mrd_modules_desc{$_} . '" ';

		if ($input->{$_}) {
			$command .= 'on';
		} else {
			$command .= 'off';
		}
	}

	$res = run_menu $command;

	if (!$res) {
		foreach (@mrd_modules) {
			$input->{$_} = 0;
		}

		foreach (split (/ /, $menu_result)) {
			$input->{$_} = 1;
		}
	}

	$state = FIRST_MENU;
}

sub advanced_menu {
	my $command = "$dialog --single-quoted --title \"Advanced Options\" --checklist \"$choose_msg\" 0 0 0";

	foreach (@adv_options) {
		$command .= ' "' . $_ . '" "' . $adv_options_desc{$_} . '" ';
		if ($adv_options_values{$_}) {
			$command .= 'on';
		} else {
			$command .= 'off';
		}
	}

	if (!run_menu $command) {
		foreach (@adv_options) {
			$adv_options_values{$_} = 0;
		}
		foreach (split (/ /, $menu_result)) {
			$adv_options_values{$_} = 1;
		}
	}

	$state = FIRST_MENU;
}

sub load_module_options {
	foreach my $mod (@modules) {
		if (open F, "< src/$mod/Module.options") {
			while (<F>) {
				if ($_ =~ m/^boolean ([A-Z]+) default (on|off) description "([^"]+)"$/) {
					$module_options{$mod}{$1}{'description'} = $3;
					$module_options{$mod}{$1}{'default'} = $2;
					$module_options{$mod}{$1}{'value'} = $2;
				}
			}

			close F;
		}
	}
}

sub module_options_menu {
	my $command = "$dialog --single-quoted --title \"" . (uc $menu_result) . " module options\" --checklist \"$choose_msg\" 0 0 0";

	my $ref = $module_options{$menu_result};

	my @keys = sort keys %$ref;

	foreach my $key (@keys) {
		my $col = $ref->{$key};

		$command .= ' "' . $key . '" "' . $col->{'description'} . '" ' . $col->{'value'};
	}

	if (!run_menu $command) {
		foreach (@keys) {
			$ref->{$_}->{'value'} = 'off'; # $ref->{$_}->{'default'};
		}
		foreach (split (/ /, $menu_result)) {
			$ref->{$_}->{'value'} = 'on';
		}
	}

	$state = FIRST_MENU;
}

sub write_config {
	if (!open F, '> src/Makefile.options') {
		print 'Failed to open Makefile.options for writing.', "\n";
		exit 1;
	}

	print F "PREFIX = $prefix\n";

	if (!$enable_modules) {
		print F "SUPPORT_MODULES = no\n";
	}

	if ($use_opts) {
		print F "OPTIMIZE = yes\n";

		if ($use_space_opts) {
			print F "SPACE_OPTIMIZE = yes\n";
		}
	}

	print F "STATIC_MODULES =";

	foreach (@mrd_modules) {
		if ($static_modules{$_}) {
			print F ' ', (uc $_);
		}
	}

	print F "\nMODULES =";

	if ($enable_modules) {
		foreach (@mrd_modules) {
			if ($external_modules{$_}) {
				print F ' ', (uc $_);
			}
		}
	}

	print F "\n";

	print F "\nMODULE_OPTIONS =";

	foreach (@modules) {
		if (_is_module_enabled $_) {
			my $mod = $_;
			my $ref = $module_options{$mod};

			my @keys = keys %$ref;

			foreach (@keys) {
				my $def = $ref->{$_}->{'default'};

				if (defined $def and ($ref->{$_}->{'value'} ne $def)) {
					print F ' ' . (uc $mod) . '_';
					if ($def eq 'on') {
						print F 'NO_';
					}
					print F $_;
				}
			}
		}
	}

	print F "\n";

	if ($adv_options_values{'NO_INLINE'}) {
		print F "NO_INLINE = yes\n";
	}

	close F;

	print 'Wrote the configuration to src/Makefile.options', "\n";
}

sub parse_current_config {
	if (open F, '< src/Makefile.options') {
		while (<F>) {
			if ($_ =~ m/^([A-Z_]+) = ([0-9A-Za-z_\$\(\)\/\. ]+)$/) {
				if ($1 eq 'SUPPORT_MODULES') {
					$enable_modules = $2 eq 'yes';
				} elsif ($1 eq 'OPTIMIZE') {
					$use_opts = $2 eq 'yes';
				} elsif ($1 eq 'SPACE_OPTIMIZE') {
					$use_space_opts = $2 eq 'yes';
				} elsif ($1 eq 'NO_INLINE') {
					$adv_options_values{$1} = $2 eq 'yes';
				} elsif ($1 eq 'PREFIX') {
					$prefix = $2;
				} elsif ($1 eq 'STATIC_MODULES') {
					foreach (@mrd_modules) {
						$static_modules{$_} = 0;
					}
					foreach (split (/ /, $2)) {
						if ($_ =~ m/([A-Z]+)/) {
							$static_modules{lc $1} = 1;
						}
					}
				} elsif ($1 eq 'EXTERNAL_MODULES') {
					foreach (@mrd_modules) {
						$external_modules{$_} = 0;
					}
					foreach (split (/ /, $2)) {
						if ($_ =~ m/([A-Z]+)/) {
							$external_modules{lc $1} = 1;
						}
					}
				} elsif ($1 eq 'MODULE_OPTIONS') {
					foreach (split (/ /, $2)) {
						if ($_ =~ m/([A-Z]+)_([A-Z_]+)/) {
							my $ref = $module_options{lc $1};

							#continue if not defined $ref;

							my $not = 0;
							my $name = $2;

							if ($name =~ m/NO_([A-Z]+)/) {
								$not = 1;
								$name = $1;
							}

							if ($not) {
								$ref->{$name}->{'value'} = 'off';
							} else {
								$ref->{$name}->{'value'} = 'on';
							}
						}
					}
				}
			}
		}

		close F;
	}
}

sub save_config {
	write_config;
}

sub ask_write_config {
	my $res = run_menu "$dialog --title \"MRD6 Configuration\" --yesno \"Write the new configuration to disk?\" 7 50";

	save_config if !$res;

	exit 0;
}

if (!open F, '< src/Makefile') {
	print 'Not running the configuration from the proper directory', "\n";
	exit 1;
}

close F;

load_module_options;
parse_current_config;

if (scalar(@ARGV) > 1) {
	my $count = scalar @ARGV;
	my $i = 0;

	# Disable all modules by default
	foreach (@mrd_modules) {
		$static_modules{$_} = 0;
		$external_modules{$_} = 0;
	}

	# This piece of code isn't luser-safe
	while ($i < $count) {
		if ($ARGV[$i] eq '--prefix') {
			$prefix = $ARGV[$i + 1];
		} elsif ($ARGV[$i] eq '--static') {
			$static_modules{$ARGV[$i + 1]} = 1;
		} elsif ($ARGV[$i] eq '--external') {
			$external_modules{$ARGV[$i + 1]} = 1;
		} elsif ($ARGV[$i] eq '--optimizations') {
			$use_opts = 1;
			if ($ARGV[$i + 1] eq 'none') {
				$use_opts = 0;
			} elsif ($ARGV[$i + 1] eq 'space') {
				$use_space_opts = 1;
			} else {
				$use_space_opts = 0;
			}
		} elsif ($ARGV[$i] eq '--option') {
			$adv_options_values{$ARGV[$i + 1]} = 1;
		} elsif ($ARGV[$i] eq '--module-option') {
			if ($ARGV[$i + 1] =~ m/([A-Z]+)_([A-Z_]+)/) {
				my $ref = $module_options{lc $1};

				my $not = 0;
				my $name = $2;

				if ($name =~ m/NO_([A-Z]+)/) {
					$not = 1;
					$name = $1;
				}

				if ($not) {
					$ref->{$name}->{'value'} = 'off';
				} else {
					$ref->{$name}->{'value'} = 'on';
				}
			}
		} elsif ($ARGV[$i] eq '--support-modules') {
			$enable_modules = $ARGV[$i + 1] eq 'yes';
		} else {
			print "Bad option ", $ARGV[$i], "\n";
			exit 1;
		}

		$i += 2;
	}

	save_config;

	exit 0;
}

check_dialog;

while (1) {
	if ($state == FIRST_MENU) {
		first_menu;
	} elsif ($state == STATIC_MODULE_MENU) {
		module_menu \%static_modules;
	} elsif ($state == DYN_MODULE_MENU) {
		module_menu \%external_modules;
	} elsif ($state == ASK_WRITE_CONFIG) {
		ask_write_config;
	} elsif ($state == ADVANCED_MENU) {
		advanced_menu;
	} elsif ($state == MODULE_OPTIONS_MENU) {
		module_options_menu;
	}
}


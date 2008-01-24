/*
 * Multicast Routing Daemon (MRD)
 *   main.cpp
 *
 * Copyright (C) 2006, 2007 - Hugo Santos
 * Copyright (C) 2004..2006 - Universidade de Aveiro, IT Aveiro
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Hugo Santos <hugo@fivebits.net>
 */

#include <mrd/mrd.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <map>

void usage() {
	printf("Usage: mrd [OPTIONS...]\n\n");
	printf("  -D        run in the background\n");
	printf("  -A        don't auto-load static modules\n");
	printf("  -f        configuration file to use. mrd.conf is used by default\n");
	printf("  -h        this screen\n");
}

int main(int argc, char **argv) {
	mrd m;

	static option longopts[] = {
		{ "help", 0, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	int c, optint;
	bool forkself = false;
	bool autoload = true;
	const char *conffile = 0;

	while ((c = getopt_long(argc, argv, "DAhf:m:", longopts, &optint)) != -1) {
		switch (c) {
		case 'D':
			forkself = true;
			break;
		case 'A':
			autoload = false;
			break;
		case 'h':
			usage();
			return 1;
		case 'f':
			conffile = optarg;
			break;
		case 'm':
			m.load_early_module(optarg);
			break;
		}
	}

	if (forkself) {
		if (daemon(1, 0) != 0) {
			fprintf(stderr, "(MRD) failed to daemonize.");
			return -1;
		}
	}

	if (!m.check_startup(conffile, autoload)) {
		return -1;
	}

	m.start();

	return 0;
}


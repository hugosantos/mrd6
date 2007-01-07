/*
 * Multicast Routing Daemon (MRD)
 *   unix_console.cpp
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

#include <mrdpriv/console/console.h>

#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <grp.h>

extern const char *socketPath;

extern console_module *console;

bool __console_allow_local(const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	group *grp = getgrnam(args[0].c_str());
	if (!grp)
		return false;

	if (chown(socketPath, 0, grp->gr_gid) != 0)
		return false;

	return chmod(socketPath, 0660) == 0;
}

unix_console_connection::unix_console_connection(mrd *core, int fd)
	: console_connection(core, fd) {
	autoclose = true;
}

void unix_console_connection::flushed(const char *str, bool newline) {
	writeclient(str);
	if (newline)
		writeclient("\n");
}

void unix_console_connection::process_input(int len) {
	int st = 0;

	while (st < len) {
		int i;

		for (i = st; i < len; i++) {
			if (buffer[i] == '\n' || buffer[i] == ';' || buffer[i] == '?') {
				break;
			}
		}

		if (buffer[i] == '?') {
			//std::string in((const char *)buffer + st, i - st);
			std::string in((const char *)buffer + st, (i + 1) - st);

			dump_partial(in.c_str());
		} else if ((i - st) > 0) {
			if (buffer[i] == '\n')
				i--;
			std::string in((const char *)buffer + st, i - st);
			process_line(in.c_str());
		}

		st = i + 1;
	}

	if (autoclose) {
		if (bufbuffer.empty())
			console->release_connection(this);
		else
			doom();
	}
}

void unix_console_connection::release() {
	delete this;
}


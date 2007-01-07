/*
 * Multicast Routing Daemon (MRD)
 *   telnet_console.cpp
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

#ifndef CONSOLE_NO_TELNET

#include <mrdpriv/console/console.h>

#include <arpa/telnet.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <ctype.h>

telnet_console_connection::telnet_console_connection(mrd *core, int fd,
						     const inet6_addr &addr,
						     uint32_t timeout)
	: console_connection(core, fd),
	  conn_timer("console conn timeout", this,
		std::mem_fun(&telnet_console_connection::release_connection),
		timeout * 60000, false),
	  c_peeraddr(addr) {
	pmode = 0;
	will_echo = false;
	should_echo = true;
	is_doomed = false;

	authenticate_state = 0;

	history_pos = 0;
}

telnet_console_connection::~telnet_console_connection() {
}

void telnet_console_connection::release_connection() {
	console->release_connection(this);
}

bool telnet_console_connection::check_startup() {
	if (!console_connection::check_startup())
		return false;

	conn_timer.start();

	cmd(WILL, TELOPT_ECHO);
	cmd(WILL, TELOPT_SGA);

	set_prompt("Username: ");

	return true;
}

void telnet_console_connection::release() {
	if (console->should_log(DEBUG))
		console->log().xprintf("(CONSOLE) releasing connection from "
				       "%{Addr}.\n", peeraddr());

	console_connection::release();
}

bool telnet_console_connection::authenticate(const char *in) {
	bool denied = false;
	std::string password;

	writeclient("\r\n");

	authenticate_state++;

	if (authenticate_state == WaitingPassword) {
		username = in;
		set_prompt("Password: ");
		should_echo = false;
	}

	if (!console->password_for(c_peeraddr, username.c_str(), password)) {
		denied = true;
	} else {
		if (authenticate_state == GotAllData) {
			denied = password != in;
		} else {
			if (password.empty() || password == "*") {
				authenticate_state++;
			}
		}
	}

	if (denied) {
		clearline();
		writeclient("Your connection is not permited. Contact the system administrator.\r\n");
		if (console->should_log(VERBOSE))
			console->log().xprintf("(CONSOLE) denied connection"
					       " from %{Addr}\n", c_peeraddr);
		console->release_connection(this);
		return false;
	} else if (authenticate_state == GotAllData) {
		writeclient("\r\n");

		g_mrd->show_mrd_version(_output);
		_output.newl();

		set_prompt("# ");
		should_echo = true;
	}

	return true;
}

void telnet_console_connection::process_input(int len) {
	input_is_updated = false;

	int last = -1;

	int i, min_was = inputbuf.size();
	int was_input = inputbuf.size();

	for (i = 0; i < len; i++) {
		if (pmode == 0) {
			if ((buffer[i] == '\n' || buffer[i] == 0) && last == '\r') {
				if (!process_line(inputbuf.c_str())) {
					shutdown();
					delete this;
					return;
				}
				inputbuf = ""; // eh.. g++ 2.95's libstdc++ doesn't have string::clear()
			} else if (buffer[i] == '\r') {
			} else if (buffer[i] == 4) { // Ctrl-D
				console->release_connection(this);
				return;
			} else if (buffer[i] == IAC) {
				pmode = 1;
			} else if (buffer[i] == 127 || buffer[i] == 8) {
				if (!inputbuf.empty()) {
					inputbuf.resize(inputbuf.size() - 1);
					if ((int)inputbuf.size() < min_was)
						min_was = inputbuf.size();
				}
			} else {
				bool eat = false;
				if (authenticate_state == GotAllData) {
					if (buffer[i] == '\t') {
						if (tabcomplete())
							redisplay_input();
					} else if (buffer[i] == '?') {
						std::string wki = inputbuf;
						wki += '?';
						writeclient("?\r\n");
						dump_partial(wki.c_str());
						redisplay_input();
					} else if (isprint(buffer[i])) {
						eat = true;
					} else if (buffer[i] == 21) {
						/* Control-U */

						inputbuf.clear();
						clearline();
						redisplay_input();
					} else if (buffer[i] == 23) {
						/* Control-W */

						int i = inputbuf.size();
						for (; i > 0 && isspace(inputbuf[i-1]); i--);
						for (; i > 0 && !isspace(inputbuf[i-1]); i--);
						inputbuf.resize(i);
						clearline();
						redisplay_input();
					} else if (buffer[i] == '\033') {
						/* <ESC> */

						/* VT100 command */
						if ((len - i) >= 3) {
							if (buffer[i+1] == '[') {
								if (buffer[i+2] == 'A') {
									/* Up */
									history_up();
								} else if (buffer[i+2] == 'B') {
									/* Down */
									history_down();
								}
							}

							i += 2;
						}
					}
				} else {
					eat = true;
				}
				if (eat)
					inputbuf.push_back(buffer[i]);
			}
		} else if (pmode == 1) {
			ctlbuf.push_back(buffer[i]);
			if (process_cmd() && ctlbuf.empty())
				pmode = 0;
		}
		last = buffer[i];
	}

	// Ugly code ahead.
	if (should_echo && !input_is_updated) {
		std::string buf;
		for (i = min_was; i < was_input; i++) {
			buf.push_back('\b');
		}
		int len = inputbuf.size();
		if (len >= was_input) {
			for (i = min_was; i < len; i++) {
				buf.push_back(inputbuf[i]);
			}
		} else {
			for (i = len; i < was_input; i++) {
				buf.push_back(' ');
			}
			for (i = len; i < was_input; i++) {
				buf.push_back('\b');
			}
		}
		writeclient(buf.c_str());
	}
}

bool telnet_console_connection::process_cmd() {
	if (ctlbuf.size() < 1)
		return false;

	switch (ctlbuf[0]) {
	case DO:
		if (ctlbuf.size() < 2)
			return false;

		if (ctlbuf[1] == TELOPT_ECHO) {
			will_echo = true;
		}

		ctlbuf.pop_front();
		ctlbuf.pop_front();

		return true;
	case SB:
		if (ctlbuf.size() < 2)
			return false;

		if (ctlbuf[1] == TELOPT_NAWS) {
			if (ctlbuf.size() < 6)
				return false;
			for (int i = 0; i < 6; i++)
				ctlbuf.pop_front();
			return true;
		}
		break;
	case SE:
		ctlbuf.pop_front();
		return true;
	}

	return false;
}

bool telnet_console_connection::process_line(const char *in) {
	conn_timer.restart();

	if (authenticate_state < GotAllData) {
		return authenticate(in);
	}

	if (should_echo)
		writeclient("\r\n");

	bool res = console_connection::process_line(in);

	if (res)
		show_prompt();

	history.push_back(in);
	history_pos = history.size();

	return res;
}

extern bool partial_match(const char *, const char *);

bool telnet_console_connection::tabcomplete() {
	if (inputbuf.empty())
		return false;

	parser_context ctx(inputbuf.c_str());

	node *n;

	bool ro = false;

	std::string lasttent;
	int res = transform(&ctx, g_mrd, node::method, n, lasttent);

	if (ctx.current_column() != (int)inputbuf.size()) {
		node::content_type ctype;
		const char *cmatch;

		res = n->match_property(node::method, ctx.head().value.c_str(),
					ctype, cmatch);

		if (res == 1 && ctype == node::method && !strcmp(cmatch, "show")) {
			res = transform(&ctx, n, node::info_method, n, lasttent);
			ro = true;
		}
	}

	/* if not all buffer was consumed, we can't really complete */
	if (ctx.current_column() != (int)inputbuf.size())
		return false;

	if (res == END_LINE) {
		/* grunf */
		if (!isspace(inputbuf[inputbuf.size()-1])) {
			inputbuf.resize(inputbuf.size() - lasttent.size());
			inputbuf += n->name();
			inputbuf += " ";
		}
	} else if (res == OK) {
		node::content_type ctype;
		const char *cmatch;

		res = n->match_property(node::child
					| (ro ? node::info_method : node::method),
					ctx.head().value.c_str(),
					ctype, cmatch);
		if (res == 0) {
			return false;
		} else if (res == 1) {
			int pos = ctx.current_column() - ctx.head().value.size();

			/* if end-of-input */
			if (ctx.eat() == 0) {
				inputbuf.resize(pos);
				inputbuf += cmatch;
				inputbuf += " ";
			}

			return true;
		} else {
			res = CONSISTENCY_ERROR;
		}
	}

	if (res == CONSISTENCY_ERROR) {
		std::string base;
		int count = 0;

		writeclient("\r\n");

		for (node::properties::const_iterator i = n->get_properties().begin();
				i != n->get_properties().end(); ++i) {
			if (i->second.is_child() || (i->second.is_method() && i->second.is_readonly() == ro)) {
				if (partial_match(lasttent.c_str(), i->first.c_str())) {
					_output.xprintf("%s ", i->first.c_str());
					count++;

					if (base.empty())
						base = i->first;
					else {
						int cn;
						int alen = base.size(), blen = i->first.size();

						/* least common denominator */
						for (cn = 0; cn < alen && cn < blen
							&& base[cn] == i->first[cn]; cn++);

						if (cn < alen)
							base.resize(cn);
					}
				}
			}
		}

		if (count) {
			_output.newl();

			if (!base.empty() && base != lasttent) {
				inputbuf.resize(inputbuf.size() - lasttent.size());
				inputbuf += base;
			}
		}
	}

	return true;
}

void telnet_console_connection::show_prompt() {
	clearline();
	writeclient(prompt.c_str());
}

void telnet_console_connection::set_prompt(const char *p) {
	prompt = p;
	show_prompt();
}

void telnet_console_connection::clearline() {
	unsigned char op[5];

	/* ANSI/VT100 erase line */

	op[0] = '\033';
	op[1] = '[';
	op[2] = '2';
	op[3] = 'K';
	op[4] = '\r';

	send(sock.fd(), op, 5, MSG_DONTWAIT);
}

void telnet_console_connection::cmd(char c, char opt) {
	char code[3];

	code[0] = IAC;
	code[1] = c;
	code[2] = opt;

	send(sock.fd(), code, 3, MSG_DONTWAIT);
}

void telnet_console_connection::redisplay_input() {
	writeclient("\r");
	writeclient(prompt.c_str());
	writeclient(inputbuf.c_str());

	input_is_updated = true;
}

void telnet_console_connection::flushed(const char *str, bool newline) {
	writeclient(str);
	if (newline)
		writeclient("\r\n");
}

void telnet_console_connection::history_up() {
	if (history_pos == 0)
		return;

	if (history_pos == (int)history.size()) {
		tmp_inputbuf = inputbuf;
	}

	history_pos--;

	inputbuf = history[history_pos];

	clearline();
	redisplay_input();
}

void telnet_console_connection::history_down() {
	if (history_pos >= (int)history.size())
		return;

	history_pos++;

	if (history_pos == (int)history.size()) {
		inputbuf = tmp_inputbuf;
	} else {
		inputbuf = history[history_pos];
	}

	clearline();
	redisplay_input();
}

void telnet_console_connection::dump_history(base_stream &out) const {
	for (std::vector<std::string>::const_iterator i = history.begin();
			i != history.end(); ++i) {
		out.writeline(i->c_str());
	}
}

void telnet_console_connection::log(bool end) {
	if (!end)
		clearline();
	else
		redisplay_input();
}

#endif


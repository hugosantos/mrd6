/*
 * Multicast Routing Daemon (MRD)
 *   console.cpp
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
#include <mrd/router.h>
#include <mrd/timers.h>
#include <mrd/interface.h>
#include <mrd/group.h>

#include <mrdpriv/console/console.h>

#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <cstring>
#include <cstdarg>

#include <algorithm>
#include <list>
#include <set>
#include <string>

enum {
	console_method_allow_access = 1000,
	console_method_deny_access,
	console_method_allow_local_access,
	console_method_attach_log,
	console_method_show_history
};

static const method_info console_methods[] = {
	{ "allow-access", "Adds a console ACL entry",
		console_method_allow_access, false, 0 },
	{ "deny-access", "Removes a console ACL entry",
		console_method_deny_access, false, 0 },
	{ "allow-local-access", "Adds local access to a system group",
		console_method_allow_local_access, false, 0 },
	{ "monitor", "Monitors log output in the console terminal",
		console_method_attach_log, false, property_def::NEGATE },
	{ "history", "Displays a list of previous commands",
		console_method_show_history, true, 0 },
	{ 0 }
};

const char *socketPath = "/var/run/mrd6";

extern bool __console_allow_local(const std::vector<std::string> &);

console_module *console;

static const char *s_b = "\033[1m";
static const char *e_b = "\033[0m";

bool partial_match(const char *base, const char *oper) {
	return strncmp(base, oper, strlen(base)) == 0;
}

module_entry(console, console_module);

console_module::console_module(mrd *m, void *dlh)
	: mrd_module(m, dlh), node(m, "console"),
#ifndef CONSOLE_NO_TELNET
	  srvsock("console listener", this,
		std::mem_fun(&console_module::new_client)),
#endif
	  unix_srvsock("unix console listener", this,
		std::mem_fun(&console_module::new_unix_client)) {

	console = this;
}

console_module::~console_module() {
}

const char *console_module::description() const {
	return "Interactive configuration";
}

bool console_module::check_startup() {
	if (!node::check_startup())
		return false;

	import_methods(console_methods);

	if (!instantiate_property_u("client-timeout", 5))
		return false;

	int one = 1;

#ifndef CONSOLE_NO_TELNET
	int sock = socket(PF_INET6, SOCK_STREAM, 0);
	if (sock < 0)
		return false;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	sockaddr_in6 lhaddr;
	memset(&lhaddr, 0, sizeof(lhaddr));

	lhaddr.sin6_family = PF_INET6;
	lhaddr.sin6_addr = in6addr_any;
	lhaddr.sin6_port = ntohs(44510);

	if (bind(sock, (sockaddr *)&lhaddr, sizeof(lhaddr)) < 0) {
		close(sock);
		return false;
	}

	if (listen(sock, 5) < 0) {
		close(sock);
		return false;
	}

	srvsock.register_fd(sock);
#endif

	int unixsock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (unixsock < 0) {
	} else {
		setsockopt(unixsock, SOL_SOCKET, SO_REUSEADDR,
			   &one, sizeof(one));

		sockaddr_un unlhaddr;
		memset(&unlhaddr, 0, sizeof(unlhaddr));
		unlhaddr.sun_family = PF_LOCAL;
		strcpy(unlhaddr.sun_path, socketPath);

		unlink(socketPath);

		if (bind(unixsock, (sockaddr *)&unlhaddr,
			 sizeof(unlhaddr)) < 0) {
			/* empty */
		} else {
			if (listen(unixsock, 5) < 0) {
				if (should_log(WARNING))
					log().writeline("Failed to listen in UNIX socket.");
			} else {
				unix_srvsock.register_fd(unixsock);
			}
		}
	}

	m_mrd->add_child(this);

	return true;
}

void console_module::shutdown() {
#ifndef CONSOLE_NO_TELNET
	if (srvsock.fd() > 0) {
		::shutdown(srvsock.fd(), SHUT_RDWR);
		srvsock.unregister();
	}
#endif

	if (unix_srvsock.fd() > 0) {
		unix_srvsock.unregister();
		unlink(socketPath);
	}

	for (std::list<console_connection *>::iterator k = connections.begin();
			k != connections.end(); ++k) {
		(*k)->shutdown();
		delete *k;
	}
	connections.clear();
}

bool console_module::call_method(int id, base_stream &out,
				 const std::vector<std::string> &args) {

	switch (id) {
	case console_method_allow_access:
		return allow_addr(args);
	case console_method_deny_access:
		return deny_addr(args);
	case console_method_allow_local_access:
		return allow_local(args);
	case console_method_attach_log:
		return attach_log(out, args);
	case console_method_show_history:
		if (!args.empty())
			return false;
		return show_history(out);
	}

	return node::call_method(id, out, args);
}

bool console_module::negate_method(int id, base_stream &out,
				   const std::vector<std::string> &args) {
	if (id == console_method_attach_log) {
		if (!args.empty())
			return false;

		console_connection *conn = calling_connection(out);
		if (!conn || !conn->clog)
			return false;

		log_base::instance().dettach_node(conn->clog);
		conn->clog = 0;

		return true;
	}

	return node::negate_method(id, out, args);
}

bool console_module::output_info(base_stream &ctx, const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	ctx.writeline("Console");

	ctx.inc_level();

	ctx.writeline("Allowed:");

	ctx.inc_level();

	if (acl.empty()) {
		ctx.writeline("(None)");
	} else {
		for (allow_local_def::const_iterator i = acl.begin();
				i != acl.end(); i++) {
			for (std::list<auth_desc>::const_iterator j =
				i->second.begin(); j != i->second.end(); j++) {
				if (j->username.empty() || j->username == "*")
					ctx.write("Any");
				else
					ctx.write(j->username.c_str());
				if (j->password.empty() || j->password == "*")
					ctx.write(" with no password");

				ctx.xprintf(" from %{Addr}\n", i->first);
			}
		}
	}

	ctx.dec_level();

	ctx.dec_level();

	return true;
}

bool console_module::allow_addr(const std::vector<std::string> &args) {
	inet6_addr mask = inet6_addr(in6addr_any, 0);

	auth_desc desc;

	if (!args.empty()) {
		desc.username = args[0];
		if (args.size() > 1) {
			desc.password = args[1];
			if (args.size() > 2) {
				if (!mask.set(args[2]))
					return false;
			}
		}
	} else {
		return false;
	}

	acl[mask].push_back(desc);

	return true;
}

bool console_module::deny_addr(const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	std::string username = args[0];

	inet6_addr mask = inet6_addr(in6addr_any, 0);

	if (args.size() > 1) {
		if (!mask.set(args[1])) {
			return false;
		}
	}

	console_module::allow_local_def::iterator i = acl.begin();

	while (i != acl.end()) {
		allow_local_def::iterator m = i;
		++i;

		if (mask.matches(m->first)) {
			std::list<auth_desc>::iterator j = m->second.begin();

			while (j != m->second.end()) {
				std::list<auth_desc>::iterator k = j;
				++j;

				if (username.empty() || username == "*"
					|| username == j->username) {
					m->second.erase(k);
				}
			}

			if (m->second.empty()) {
				acl.erase(m);
			}
		}
	}

	return true;
}

bool console_module::allow_local(const std::vector<std::string> &args) {
	return __console_allow_local(args);
}

console_connection *console_module::calling_connection(base_stream &out) const {
	/* hack to find calling console connection */
	base_stream *_b = &out;

	for (std::list<console_connection *>::const_iterator i =
		connections.begin(); i != connections.end(); ++i) {
		console_connection *cc = *i;

		/* hackish, we find the calling console_connection
		 * by matching the current output stream vs. each
		 * of the console_connection's output stream */

		if (_b == &cc->_output)
			return cc;
	}

	return 0;

}

bool console_module::attach_log(base_stream &out,
				const std::vector<std::string> &args) {
	if (args.size() > 1)
		return false;

	const char *level = "extradebug";
	if (!args.empty()) {
		int tmp;
		if (!log_node::parse_infolevel(args[0].c_str(), tmp))
			return false;
		level = args[0].c_str();
	}

	console_connection *cc = calling_connection(out);

	if (cc) {
		if (cc->clog)
			log_base::instance().dettach_node(cc->clog);

		cc->clog = new console_log_node(cc);
		if (!cc->clog)
			return false;

		char name[64];
		snprintf(name, sizeof(name), "console-%i", cc->sock.fd());

		cc->clog->rename(name);
		cc->clog->set_level(level);

		if (log_base::instance().attach_node(cc->clog)) {
			cc->autoclose = false;
			return true;
		}
	}

	return false;
}

bool console_module::show_history(base_stream &out) {
	console_connection *cc = calling_connection(out);

	if (!cc)
		return false;

	cc->dump_history(out);

	return true;
}

#ifndef CONSOLE_NO_TELNET
void console_module::new_client(uint32_t) {
	sockaddr_in6 from;
	socklen_t fromlen = sizeof(from);

	memset(&from, 0, sizeof(from));
	from.sin6_family = PF_INET6;

	int foo = accept(srvsock.fd(), (sockaddr *)&from, &fromlen);
	if (foo < 0) {
		return;
	}

	if (fromlen != sizeof(sockaddr_in6)) {
		close(foo);
		return;
	}

	if (should_log(DEBUG))
		log().xprintf("(CONSOLE) New connection from %{addr}\n",
			      from.sin6_addr);

	uint32_t tim = get_property_unsigned("client-timeout");

	console_connection *conn =
		new telnet_console_connection(m_mrd, foo, from.sin6_addr, tim);

	if (conn && conn->check_startup()) {
		connections.push_back(conn);

		return;
	}

	delete conn;
	close(foo);
}
#endif

void console_module::new_unix_client(uint32_t) {
	sockaddr_un from;
	socklen_t fromlen = sizeof(from);

	memset(&from, 0, sizeof(from));
	from.sun_family = PF_LOCAL;

	int foo = accept(unix_srvsock.fd(), (sockaddr *)&from, &fromlen);
	if (foo < 0) {
		return;
	}

	console_connection *conn = new unix_console_connection(m_mrd, foo);

	if (conn && conn->check_startup()) {
		connections.push_back(conn);

		return;
	}

	delete conn;
	close(foo);
}

void console_module::release_connection(console_connection *conn) {
	for (std::list<console_connection *>::iterator i = connections.begin();
			i != connections.end(); ++i) {
		if (*i == conn) {
			conn->shutdown();
			conn->release();
			connections.erase(i);
			return;
		}
	}
}

bool console_module::password_for(const inet6_addr &addr, const char *username,
				  std::string &passwd) const {
	for (allow_local_def::const_iterator i =
			acl.begin(); i != acl.end(); ++i) {
		if (i->first.matches(addr)) {
			for (std::list<auth_desc>::const_iterator j =
				i->second.begin(); j != i->second.end(); ++j) {
				if (j->username == username) {
					passwd = j->password;
					return true;
				}
			}

			for (std::list<auth_desc>::const_iterator j =
				i->second.begin(); j != i->second.end(); ++j) {
				if (j->username == "*" || j->username.empty()) {
					passwd = j->password;
					return true;
				}
			}
		}
	}

	return false;
}

console_log_node::console_log_node(console_connection *conn)
	: tb_log_node(&log_base::instance(), "console", EVERYTHING), _conn(conn) {}

void console_log_node::rename(const char *n) {
	m_name = n;
}

void console_log_node::log(int, int, const char *buf, bool newline) {
	if (newline) {
		_conn->log(false);
		char buf[64];
		_conn->_output.printf("- LOG %s- ", timestamp(buf, sizeof(buf)));
		if (!_buf.empty())
			_conn->_output.append_chunk(_buf.c_str(), _buf.size());
		_conn->_output.write(buf);
		if (newline)
			_conn->_output.newl();
		_conn->log(true);
		_buf = "";
	} else {
		_buf += buf;
	}
}

console_connection::console_connection(mrd *core, int s)
	: m_mrd(core), sock("console connection", this,
	std::mem_fun(&console_connection::data_available)), _output(this) {

	is_doomed = false;

	clog = 0;

	autoclose = false;

	sock.register_fd(s);
}

void console_connection::doom() {
	is_doomed = true;
}

bool console_connection::check_startup() {
	return true;
}

void console_connection::shutdown() {
	if (sock.fd() > 0) {
		::shutdown(sock.fd(), SHUT_RDWR);
		sock.unregister();
	}

	if (clog) {
		log_base::instance().dettach_node(clog);
		clog = 0;
	}
}

void console_connection::release() {
	doom();
}

void console_connection::data_available(uint32_t flags) {
	if (flags == socket_base::Write) {
		if (!bufbuffer.empty()) {
			int k = send(sock.fd(), bufbuffer.c_str(),
				     bufbuffer.size(), MSG_DONTWAIT);
			if (k > 0) {
				bufbuffer.erase(0, k);
			}
		}

		if (bufbuffer.empty()) {
			if (is_doomed)
				console->release_connection(this);
			else
				sock.monitor(socket_base::Read);
		}

		return;
	}

	int len = recv(sock.fd(), buffer, sizeof(buffer), 0);

	if (len <= 0) {
		console->release_connection(this);
		return;
	}

	process_input(len);
}

bool console_connection::process_line(const char *in) {
	parser_context ctxcn(in);
	process_deep_line(&ctxcn);

	return !is_doomed;
}

void console_connection::process_deep_line(parser_context *ctx) {
	int res = advance_one(ctx, g_mrd);
	if (res == -1) {
		_output.writeline("\% Error in input.");
	}
}

int console_connection::check_termination(parser_context *ctx, node *n) {
	int res = ctx->eat();
	if (res < 0)
		return -1;
	return res == 0 ?
		0 : (ctx->head().sym == parser_context::TERM ?
					advance_one(ctx, n) : -1);
}

int console_connection::advance_one(parser_context *ctx, node *n) {
	int res;

	if (!n)
		n = g_mrd;

	if ((res = ctx->eat(5, parser_context::TOKEN, parser_context::LCURLY,
			       parser_context::RCURLY, parser_context::LPARENT,
			       parser_context::PARTIAL_TOKEN)) < 1) {
		return res;
	}

	node::content_type ctype;
	const char *cmatch;
	int cres = n->match_property(node::property
				     | node::method
				     | node::child,
				     ctx->head().value.c_str(),
				     ctype, cmatch);

	if (cres == 0) {
		n = n->create_child(ctx->head().value.c_str());
		if (n) {
			cres = 1;
			cmatch = ctx->head().value.c_str();
			ctype = node::child;
		}
	}

	if (cres == 0) {
		_output.writeline("% No such method/child.");
		return -2;
	} else if (cres > 1) {
		_output.xprintf("%% Inconsistency in input when parsing `%s`.\n",
				ctx->head().value.c_str());
		return -2;
	} else {
		if (ctype == node::child) {
			n = n->get_child(cmatch);
			if (!n)
				return -1;
			return advance_one(ctx, n);
		} else if (ctype == node::property) {
			if ((res = ctx->eat()) < 1)
				return res;

			n->set_property(cmatch, ctx->head().value.c_str());

			return advance_one(ctx, 0);
		} else {
			std::vector<std::string> args;

			while ((res = ctx->eat()) > 0) {
				if (ctx->head().sym == parser_context::TERM)
					break;
				args.push_back(std::string(ctx->head().value));
			}

			if (res < 0)
				return res;

			const property_def *mth = n->get_any_property(cmatch);

			if (!mth || !mth->is_method() || mth->is_readonly()) {
				_output.xprintf("%% No such method %s.\n", cmatch);
				return -2;
			} else if (!n->call_method(mth->get_method_info()->id,
						   _output, args)) {
				_output.xprintf("`%s` execution failed.\n", cmatch);
				return -2;
			}

			return advance_one(ctx, 0);
		}
	}

	return -1;
}

void console_connection::writeclient(const char *what) {
	if (!bufbuffer.empty()) {
		bufbuffer += what;
	} else {
		if (send(sock.fd(), what, strlen(what), MSG_DONTWAIT) < 0) {
			if (errno == EAGAIN) {
				bufbuffer = what;

				sock.monitor(socket_base::Read
						| socket_base::Write);
			}
		}
	}
}

void console_connection::dump_partial(const char *in) {
	parser_context ctxcn(in);

	node *n;

	int res = transform(&ctxcn, g_mrd, node::method, n);

	if (res == OK) {
		if (ctxcn.head().sym != parser_context::PARTIAL_TOKEN) {
			node::content_type ctype;
			const char *cmatch;

			res = n->match_property(node::method,
						ctxcn.head().value.c_str(),
						ctype, cmatch);

			if (res == 1 && ctype == node::method
				&& !strcmp(cmatch, "show")) {

				res = transform(&ctxcn, n,
						node::info_method, n);
				if (res == OK && ctxcn.head().sym
					== parser_context::PARTIAL_TOKEN)
					dump_partial(n, &ctxcn, true);
			}
		} else {
			dump_partial(n, &ctxcn, false);
		}
	}
}

void console_connection::dump_partial(node *n, parser_context *ctx, bool ro) {
	std::string m = ctx->head().value;

	m.resize(m.size() - 1);

	int cn = 0;

	for (node::properties::const_iterator i = n->get_properties().begin();
			i != n->get_properties().end(); ++i) {
		if (i->second.is_method() && i->second.is_readonly() != ro)
			continue;

		if (m.empty() || partial_match(m.c_str(), i->first.c_str())) {
			const char *desc = i->second.description();

			if (desc && (int)i->first.size() > cn)
				cn = i->first.size();
		}
	}

	const int Cols = 72;

	for (node::properties::const_iterator i = n->get_properties().begin();
			i != n->get_properties().end(); ++i) {
		if (i->second.is_method() && i->second.is_readonly() != ro)
			continue;

		if (m.empty() || partial_match(m.c_str(), i->first.c_str())) {
			const char *desc = i->second.description();

			if (desc) {
				_output.xprintf("  %s%s%s", s_b, i->first.c_str(), e_b);
				_output.spaces((cn + 2) - i->first.size());

				int dl = strlen(desc);
				if ((dl + cn + 4) > (Cols-1)) {
					char buf[Cols];
					int k = (sizeof(buf)-1) - cn - 4;
					int dlx = dl;
					do {
						strncpy(buf, desc, k);
						buf[k] = 0;
						_output.xprintf("%s+\n", buf);
						_output.spaces(cn + 4);
						dlx -= k;
						desc += k;
					} while (dlx > k);
				}

				_output.writeline(desc);
			}
		}
	}
}

int console_connection::transform(parser_context *ctx, node *base,
				  node::content_type m, node * &result,
				  std::string &lasttent) const {
	result = base;

	while (1) {
		int res = ctx->eat(2, parser_context::TOKEN,
				      parser_context::PARTIAL_TOKEN);
		if (res < 0)
			break;
		else if (res == 0)
			return END_LINE;
		else if (ctx->head().sym == parser_context::PARTIAL_TOKEN)
			return OK;

		node::content_type ctype;
		const char *cmatch;

		lasttent = ctx->head().value;

		int cres = result->match_property(node::child | m,
						  lasttent.c_str(),
						  ctype, cmatch);
		if (cres == 0 || (cres == 1 && ctype != node::child))
			return OK;
		else if (cres == 1) {
			result = result->get_child(cmatch);
			if (!result)
				break;
		} else {
			return CONSISTENCY_ERROR;
		}
	}

	return INPUT_ERROR;
}

int console_connection::transform(parser_context *ctx, node *base,
				  node::content_type m, node * &result) const {
	std::string tmp;

	return transform(ctx, base, m, result, tmp);
}

void console_connection::dump_history(base_stream &) const {
}

void console_connection::log(bool) {
}



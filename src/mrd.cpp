/*
 * Multicast Routing Daemon (MRD)
 *   mrd.cpp
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
#include <mrd/interface.h>
#include <mrd/group.h>
#include <mrd/router.h>
#include <mrd/timers.h>
#include <mrd/packet_buffer.h>
#include <mrd/mfa.h>
#include <mrd/rib.h>

#include <mrdpriv/icmp_inet6.h>

#include <sys/ucontext.h>

#include <vector>
#include <map>
#include <stack>

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/signal.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <pwd.h>

#include <sys/utsname.h>

#include <limits.h>

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#if !defined(SA_SIGINFO) && defined(__gnu_hurd__)
#define SA_SIGINFO 0x00000004u
#endif

#define CRASH_COMMAND

mrd *g_mrd = 0;

extern const char *BuildDate;
static const char *VersionInfo = "mrd6 0.10.0";

static const char *defaultconffiles[] = {
	"mrd6.conf",
	"mrd.conf",
	"/etc/mrd6/mrd6.conf",
	"/etc/mrd6/conf",
	"/etc/mrd6.conf",
	"/etc/mrd.conf",
	0
};

enum mrd_method_name {
	method_shutdown = 1000,
	method_version,
	method_timers,
	method_rpf,
	method_load_module,
	method_unload_module,
	method_unicast_regs,
	method_socket_regs,
	method_show_info,
	method_conf,
	method_show_commands,
	method_show,
	method_dump_tree,
#ifdef CRASH_COMMAND
	method_crash,
#endif
};

static const method_info mrd_methods[] = {
	{ "shutdown",	"Terminates the router execution",
		method_shutdown, false, property_def::COMPLETE_M },
	{ "version",	"Displays MRD6 version",
		method_version, true, 0 },
	{ "timers",	"Display timer information",
		method_timers,	true,	0 },
	{ "rpf",	"Reverse path forwarding check",
		method_rpf, true, 0 },
	{ "load-module",	0, method_load_module,	false,	0 },
	{ "unload-module",	0, method_unload_module,false,	0 },
	{ "unicast-regs",	0, method_unicast_regs,	true,	0 },
	{ "socket-regs",	0, method_socket_regs,	true,	0 },
	{ "info",		0, method_show_info,	true,	0 },
/*	{ "conf",	"Current configuration",
		method_conf, true, 0 }, */
	{ "commands",	"Display all available commands",
		method_show_commands, true, 0 },
	{ "show",	"Show running system information",
		method_show,	false, 0 },
	{ "node-tree",		0, method_dump_tree,	true,	0 },
#ifdef CRASH_COMMAND
	{ "crash",		0, method_crash,	false, property_def::COMPLETE_M },
#endif
	{ 0 }
};

enum {
	method_interfaces_disable_range = 1100,
};

static const method_info interfaces_methods[] = {
	{ "disable-range", "Adds a new regexp to ignore system interfaces",
		method_interfaces_disable_range, false, property_def::NEGATE },
	{ 0 }
};

// simple recursive parser

class conf_parser {
public:
	conf_parser();

	bool parse(const char *);

	typedef std::vector<node *> state;

	int proplist(const state &);
	int prop(const state &);
	int value();
	bool check_value(bool eat);
	int prop_type(const state &);

	int set_value(bool, const char *, const state &);

	FILE *fp;

	parser_context ctx;

	char *buffer;
	int bufsize;
};

conf_parser::conf_parser() {
	buffer = 0;
}

bool conf_parser::parse(const char *filename) {
	fp = fopen(filename, "r");
	if (!fp)
		return false;

	bool ret = false;

	if (fseek(fp, 0, SEEK_END) == 0) {
		bufsize = ftell(fp);
		if (bufsize >= 0) {
			if (fseek(fp, 0, SEEK_SET) == 0) {
				buffer = new char[bufsize+1];
				int res = fread(buffer, bufsize, 1, fp);
				buffer[bufsize] = 0;
				if (res == 1) {
					ctx = parser_context(buffer);

					state ns;
					ns.push_back(g_mrd);

					if (proplist(ns) >= 0) {
						ret = true;
					}
				}
			}
		}
	}

	delete [] buffer;
	buffer = 0;

	fclose(fp);

	return ret;
}

int conf_parser::proplist(const state &s) {
	int res;
	if ((res = prop(s)) < 1)
		return res;

	return proplist(s);
}

int conf_parser::prop(const state &s) {
	int res;
	if ((res = ctx.read()) < 1)
		return res;

	if (ctx.head().sym == parser_context::LPARENT) {
		state ns;
		ctx.eat();
		while (1) {
			if ((res = ctx.eat()) < 1)
				return res;
			if (ctx.head().sym == parser_context::RPARENT)
				break;
			else if (ctx.head().sym == parser_context::COMMA)
				continue;
			else if (!check_value(false))
				return -1;
			for (state::const_iterator i = s.begin(); i != s.end(); ++i) {
				node *n = (*i)->get_or_create_child(ctx.head().value.c_str());
				if (n) {
					ns.push_back(n);
				} else {
					if (g_mrd->should_log(EXTRADEBUG)) {
						g_mrd->log().xprintf(
						     "(CONF) %s has no child %s.\n",
						     (*i)->full_name().c_str(),
						     ctx.head().value.c_str());
					}
				}
			}

		}

		return prop(ns);
	}

	if (!check_value(true)) {
		return 0;
	}

	if ((res = prop_type(s)) < 1)
		return res;

	return 1;
}

int conf_parser::value() {
	int res;

	if ((res = ctx.read()) < 1)
		return res;

	return check_value(true) ? 1 : 0;
}

bool conf_parser::check_value(bool eat) {
	if (ctx.head().sym == parser_context::TOKEN
		|| ctx.head().sym == parser_context::STRING) {
		if (eat)
			ctx.eat();

		return true;
	}

	return false;
}

int conf_parser::set_value(bool set, const char *name, const state &s) {
	if (value() < 1)
		return -1;

	std::string val = ctx.head().value;

	if (ctx.eat(parser_context::TERM) < 1)
		return -1;

	for (state::const_iterator i = s.begin(); i != s.end(); ++i) {
		bool res;

		if (set)
			res = (*i)->set_property(name, val.c_str());
		else
			res = (*i)->increment_property(name, val.c_str());

		if (!res) {
			if (g_mrd->should_log(WARNING)) {
				g_mrd->log().xprintf("(CONF) Failed to change "
						     "property %s.\n", name);
			}
			return -1;
		}
	}

	return 1;
}

int conf_parser::prop_type(const state &s) {
	std::string ident = ctx.head().value;

	int res;

	if ((res = ctx.read()) < 1)
		return res;

	parser_context::symbol symb = ctx.head();

	if (symb.sym == parser_context::EQUAL
		|| symb.sym == parser_context::PLUSEQUAL) {

		ctx.eat();

		return set_value(symb.sym == parser_context::EQUAL, ident.c_str(), s);
	} else if (symb.sym == parser_context::LCURLY) {

		ctx.eat();

		state ns;

		for (state::const_iterator i = s.begin(); i != s.end(); ++i) {
			node *n = (*i)->get_or_create_child(ident.c_str());
			if (n)
				ns.push_back(n);
		}

		if (proplist(ns) == -1)
			return -1;

		if (ctx.eat(parser_context::RCURLY) < 1)
			return -1;
	} else {
		state ns;

		for (state::const_iterator i = s.begin(); i != s.end(); ++i) {
			node *n = (*i)->get_or_create_child(ident.c_str());
			if (n) {
				ns.push_back(n);
			} else if ((*i)->has_property(ident.c_str())) {
				if (value() < 1)
					return -1;

				std::string val = ctx.head().value;

				if (ctx.eat(parser_context::TERM) < 1)
					return -1;

				/* XXX check return value */
				(*i)->set_property(ident.c_str(), val.c_str());

			} else {
				const property_def *mth =
					(*i)->get_any_property(ident.c_str());

				if (mth && mth->is_method() && !mth->is_readonly()) {
					std::vector<std::string> args;

					while (value() > 0) {
						args.push_back(std::string(ctx.head().value));
					}

					if (ctx.eat(parser_context::TERM) < 1)
						return -1;

					if (!(*i)->call_method(mth->get_method_info()->id,
							       g_mrd->log(), args)) {
						if (g_mrd->should_log(DEBUG)) {
							g_mrd->log().xprintf(
								"(CONF) Failed while calling "
								"%s in %s.\n", ident.c_str(),
								(*i)->name());
						}
					}
				} else {
					node *p = *i;
					while (1) {
						p = p->next_similiar_node();
						if (!p) {
							return -1;
						} else if (p->has_property(ident.c_str())) {
							if (value() < 1)
								return -1;
							std::string val = ctx.head().value;
							if (ctx.eat(parser_context::TERM) < 1)
								return -1;
							(*i)->set_property(ident.c_str(), val.c_str());
							break;
						}
					}
				}
			}
		}

		if (!ns.empty())
			return prop(ns);
	}

	return 1;
}

mrd::intfconf_list::intfconf_list(node *parent)
	: node(parent, "interfaces") {}

mrd::intfconf_list::~intfconf_list() {
	for (std::list<disable_token>::iterator i =
			tokens.begin(); i != tokens.end(); ++i) {
		regfree(&i->r);
	}
	tokens.clear();
}

bool mrd::intfconf_list::check_startup() {
	if (!node::check_startup())
		return false;

	import_methods(interfaces_methods);

	return true;
}

bool mrd::intfconf_list::call_method(int id, base_stream &out,
				     const std::vector<std::string> &args) {
	if (id == method_interfaces_disable_range) {
		if (args.size() != 1)
			return false;
		tokens.push_back(disable_token());

		disable_token &tok = tokens.back();

		tok.origstr = args[0];
		if (regcomp(&tok.r, tok.origstr.c_str(),
			    REG_EXTENDED | REG_NOSUB) != 0) {
			tokens.pop_back();
			return false;
		}

		return true;
	}

	return node::call_method(id, out, args);
}

bool mrd::intfconf_list::negate_method(int id, base_stream &out,
				       const std::vector<std::string> &args) {
	if (id == method_interfaces_disable_range) {
		if (args.size() != 1)
			return false;

		for (std::list<disable_token>::iterator i =
				tokens.begin(); i != tokens.end(); ++i) {
			if (i->origstr == args[0]) {
				regfree(&i->r);
				tokens.erase(i);
				break;
			}
		}

		return true;
	}

	return node::negate_method(id, out, args);
}

bool mrd::intfconf_list::is_interface_disabled(const char *name) const {
	for (std::list<disable_token>::const_iterator i =
			tokens.begin(); i != tokens.end(); ++i) {
		if (regexec(&i->r, name, 0, 0, 0) == 0) {
			return true;
		}
	}

	return false;
}

node *mrd::intfconf_list::create_child(const char *name) {
	intfconf *conf = (intfconf *)get_child(name);
	if (!conf) {
		if (has_child_property(name))
			return 0;

		conf = new intfconf(name);

		if (!conf || !conf->check_startup()) {
			delete conf;
			return 0;
		}

		add_child(conf);

		interface *intf = g_mrd->get_interface_by_name(name);
		if (intf)
			conf->update_interface_configuration(intf);
	}

	return conf;
}

void mrd::intfconf_list::remove_child_node(node *n) {
	delete (intfconf *)n;
}

socket_base::socket_base(const char *name)
	: _name(name), _fd(-1), _hits(0) {}

socket_base::~socket_base() {
	unregister(true);
}

bool socket_base::register_fd(int sock, uint32_t flags) {
	return g_mrd->register_sock(this, sock, flags);
}

void socket_base::unregister(bool close) {
	if (_fd > 0) {
		g_mrd->unregister_sock(this);

		if (close) {
			if (g_mrd->should_log(INTERNAL_FLOW)) {
				g_mrd->log().xprintf(
					"Socket, unregister %s (%i).\n",
					name(), _fd);
			}

			::close(_fd);
			_fd = -1;
		}
	}
}

bool socket_base::monitor(uint32_t flags) {
	return g_mrd->monitor_sock(this, flags);
}

socket6_base::socket6_base(const char *name)
	: socket_base(name) {
	memset(_ctlbuf, 0, sizeof(_ctlbuf));
	memset(&_h, 0, sizeof(_h));
}

bool socket6_base::register_fd(int fd, uint32_t flags) {
	int on = 1;

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
		return false;

	return socket_base::register_fd(fd, flags);
}

int socket6_base::sendto(const void *buf, uint16_t buflen, const sockaddr_in6 *to) {
	return ::sendto(fd(), buf, buflen, 0, (const sockaddr *)to, sizeof(sockaddr_in6));
}

int socket6_base::sendto(const void *buf, uint16_t buflen,
		const sockaddr_in6 *to, const sockaddr_in6 *from, int extractl) {
	iovec v = { (void *)buf, buflen };

	_h.msg_name = (void *)to;
	_h.msg_namelen = sizeof(sockaddr_in6);
	_h.msg_iov = &v;
	_h.msg_iovlen = 1;
	_h.msg_control = _ctlbuf;
	_h.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo)) + extractl;
	_h.msg_flags = 0;

	cmsghdr *chdr = (cmsghdr *)CMSG_FIRSTHDR(&_h);
	chdr->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;

	in6_pktinfo *pktinfo = (in6_pktinfo *)CMSG_DATA(chdr);

	pktinfo->ipi6_ifindex = from->sin6_scope_id;
	pktinfo->ipi6_addr = from->sin6_addr;

	return ::sendmsg(fd(), &_h, 0);
}

int socket6_base::recvfrom(void *buf, uint16_t buflen, sockaddr_in6 *from) {
	socklen_t fromlen = sizeof(sockaddr_in6);

	return ::recvfrom(fd(), buf, buflen, 0, (sockaddr *)from, &fromlen);
}

int socket6_base::recvfrom(void *buf, uint16_t buflen) {
	iovec v = { buf, buflen };

	_h.msg_name = (void *)&_recvfrom;
	_h.msg_namelen = sizeof(sockaddr_in6);
	_h.msg_iov = &v;
	_h.msg_iovlen = 1;
	_h.msg_control = _ctlbuf;
	_h.msg_controllen = sizeof(_ctlbuf);
	_h.msg_flags = 0;

	return ::recvmsg(fd(), &_h, 0);
}

static bool _mc_method(int fd, int action, int index, const in6_addr &addr) {
	ipv6_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	mreq.ipv6mr_interface = index;
	mreq.ipv6mr_multiaddr = addr;

	return setsockopt(fd, IPPROTO_IPV6, action, &mreq, sizeof(mreq)) == 0;
}

bool socket6_base::join_mc(interface *intf, const in6_addr &addr) {
	return _mc_method(fd(), IPV6_JOIN_GROUP, intf->index(), addr);
}

bool socket6_base::leave_mc(interface *intf, const in6_addr &addr) {
	return _mc_method(fd(), IPV6_LEAVE_GROUP, intf->index(), addr);
}

bool socket6_base::enable_mc_loop(bool yes) {
	int loop = yes ? 1 : 0;

	return setsockopt(fd(), IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			&loop, sizeof(loop)) == 0;
}

bool socket6_base::set_hoplimit(int n) {
	return setsockopt(fd(), IPPROTO_IPV6, IPV6_HOPLIMIT, &n, sizeof(n)) == 0;
}

bool socket6_base::set_mcast_hoplimit(int n) {
	return setsockopt(fd(), IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &n, sizeof(n)) == 0;
}

bool socket6_base::destination_address(sockaddr_in6 &dst, int &index) {
	for (cmsghdr *hdr = CMSG_FIRSTHDR(&_h); hdr;
				hdr = CMSG_NXTHDR(&_h, hdr)) {
		if (hdr->cmsg_level == IPPROTO_IPV6
			&& hdr->cmsg_type == IPV6_PKTINFO
			&& hdr->cmsg_len == CMSG_LEN(sizeof(in6_pktinfo))) {
			in6_pktinfo *pktinfo = (in6_pktinfo *)CMSG_DATA(hdr);

			dst.sin6_family = AF_INET6;
			dst.sin6_addr = pktinfo->ipi6_addr;
			index = pktinfo->ipi6_ifindex;
			if (IN6_IS_ADDR_LINKLOCAL(&pktinfo->ipi6_addr))
				dst.sin6_scope_id = index;
			else
				dst.sin6_scope_id = 0;

			return true;
		}
	}

	return false;
}

cmsghdr *socket6_base::next_cmsghdr(int maxlen) const {
	if ((CMSG_SPACE(sizeof(in6_pktinfo)) + CMSG_SPACE(maxlen)) > sizeof(_ctlbuf))
		return NULL;

	return (cmsghdr *)(_ctlbuf + CMSG_SPACE(sizeof(in6_pktinfo)));
}

encoding_buffer::encoding_buffer(int avail) {
	m_buffer = new uint8_t[avail];

	m_end = m_buffer + avail;
	m_head = m_tail = m_buffer;
}

encoding_buffer::~encoding_buffer() {
	delete [] m_buffer;
}

bool encoding_buffer::check_startup() {
	return m_buffer != 0;
}

void *encoding_buffer::eat(int len) {
	if (!require(len))
		return 0;

	uint8_t *head = m_head;

	m_head += len;

	return head;
}

void *encoding_buffer::put(int len) {
	if (!tail_require(len))
		return 0;

	uint8_t *tail = m_tail;

	m_tail += len;

	return tail;
}

void encoding_buffer::advance_head(int len) {
	m_head += len;
}

void encoding_buffer::advance_tail(int len) {
	m_tail += len;

	// if (length > max_ptr)
	//	max_ptr = length;
}

void encoding_buffer::compact() {
	int length = m_tail - m_head;

	if (length)
		memmove(m_buffer, m_head, length);

	m_head = m_buffer;
	m_tail = m_head + length;
}

void encoding_buffer::clear() {
	m_head = m_tail = m_buffer;
}

int encoding_buffer::consume(socket_base &sk, bool blocking) {
	int len;

	if ((len = recv(sk.fd(), tail(), available_length(),
			blocking ? 0 : MSG_DONTWAIT)) > 0)
		advance_tail(len);

	return len;
}

int encoding_buffer::flush_to(socket_base &sk, bool wantsread, bool blocking) {
	int consumed = 0;

	if (!empty()) {
		consumed = send(sk.fd(), head(), data_length(),
				blocking ? 0 : MSG_DONTWAIT);
		if (consumed > 0) {
			advance_head(consumed);
			compact();
		}
	}

	if (empty())
		sk.monitor(wantsread ? socket_base::Read : 0);

	return consumed;
}

mrd::mrd()
	: node(0, "mrd"), m_state(Initial), g_rlog(this), m_mrib(this),
	  m_intflist_node(this, "interface"), m_grplist_node(this, "group"),
	  m_intfconfs(this), m_groups_node(this) {

	FD_ZERO(&m_rdst);
	FD_ZERO(&m_wrst);

	g_mrd = this;

	ipktb = new packet_buffer();
	opktb = new packet_buffer();

	add_child(&g_rlog);
	add_child(&m_mrib);

	add_child(&m_intfconfs, true);
	add_child(&m_groups_node, true);

	add_child(&m_intflist_node, false, 0, 0 /* "Display interface information" */);
	add_child(&m_grplist_node, false, 0, 0 /*"Display active group information" */);

	m_mfa = 0;
	m_rib_handler = 0;
	m_icmp = 0;

	m_largestsock = 0;

	m_module_path.push_back("/usr/local/lib/mrd6");
	m_module_path.push_back("/usr/local/lib/mrd");
	m_module_path.push_back("/usr/lib/mrd6");
	m_module_path.push_back("/usr/lib/mrd");
	m_module_path.push_back(".");

	invalidate_intf_cache();

	m_tasks_stat = 0;
	m_tasks_time_spent = 0;

	m_startup = 0;
}

mrd::~mrd() {
	delete ipktb;
	delete opktb;

	ipktb = 0;
	opktb = 0;
}

bool mrd::register_router(router *r) {
	if (!r->check_startup())
		return false;

	m_routers[r->name()] = r;

	r->attach(this);

	add_child(r);

	if (should_log(NORMAL))
		log().xprintf("Registered router %s.\n", r->name());

	intfconf_node *intfnode = ((intfconf_node *)
		g_mrd->default_interface_configuration()->create_child(r->name()));
	if (intfnode)
		intfnode->fill_defaults();

	groupconf *defaultgc = get_group_configuration(inet6_addr::any());

	groupconf_node *grpnode =
		(groupconf_node *)defaultgc->create_child(r->name());

	if (grpnode)
		grpnode->fill_defaults();

	if (m_state == Running) {
		for (interface_list::iterator i = m_intflist.begin();
					i != m_intflist.end(); i++) {
			r->event(InterfaceStateChanged, i->second);
		}
	}

	return true;
}

void mrd::unregister_router(router *r) {
	std::map<std::string, router *>::iterator i = m_routers.find(r->name());
	if (i == m_routers.end())
		return;

	m_routers.erase(i);

	remove_child(r->name());

	if (should_log(VERBOSE))
		log().xprintf("Unregistered router %s.\n", r->name());
}

router *mrd::get_router(const char *name) const {
	routers::const_iterator k = m_routers.find(name);
	if (k == m_routers.end())
		return 0;
	return k->second;
}

mrd::posix_uctx::posix_uctx(ucontext_t *ctx)
	: base(ctx) {}

static void handle_sigsegv(int id, siginfo_t *info, void *ptr) {
	ucontext_t *uc = (ucontext_t *)ptr;

	/* hopefully the logging interface will be intact */

	base_stream &out = g_mrd->fatal();

	out.writeline("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*");
	out.writeline("It seems MRD6 has crashed. Please contact either the");
	out.writeline("package maintainer or the software authors and include");
	out.writeline("the following information in your report.");

	out.writeline("---------------------- CUT HERE ----------------------");

	g_mrd->show_base_info(out);

	utsname name;

	if (uname(&name) == 0) {
		out.xprintf("System: %s %s %s %s %s\n", name.sysname,
			    name.nodename, name.release, name.version,
			    name.machine);
	}

	mrd::posix_uctx uctx(uc);

	void *PC = uctx.get_current_frame();

	out.printf("Failed when trying to access %p", info->si_addr);

	if (PC) {
		out.write(" at ");

		char *desc = g_mrd->obtain_frame_description(PC);
		if (desc) {
			out.write(desc);
			free(desc);
		} else {
			out.printf("%p", PC);
		}
	}

	out.newl().writeline("Backtrace:");

	out.inc_level();

	g_mrd->output_backtrace(out);

	out.dec_level();

	out.writeline("---------------------- CUT HERE ----------------------");

	exit(SIGSEGV);
}

static bool
get_seed_from_file(const char *path, uint32_t *value)
{
	int fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return false;

	int len = read(fd, value, 4);

	close(fd);

	return len == 4;
}

static uint32_t
get_random_seed()
{
	uint32_t value;

	if (get_seed_from_file("/dev/urandom", &value))
		return value;

	/* Not all systems have a /dev/urandom */

	if (get_seed_from_file("/dev/random", &value))
		return value;

	return time(NULL);
}

bool mrd::check_startup(const char *conffile, bool autoload) {
	change_state(PreConfiguration);

	if (!ipktb || !opktb)
		return false;

	if (!m_timermgr.check_startup())
		return false;

	if (!node::check_startup())
		return false;

	if (!g_rlog.check_startup()
		|| !m_mrib.check_startup()
		|| !m_intfconfs.check_startup()
		|| !m_groups_node.check_startup()
		|| !m_intflist_node.check_startup()
		|| !m_grplist_node.check_startup())
		return false;

	srand(get_random_seed());

	import_methods(mrd_methods);

	if (!register_source_discovery("static", &m_static_source_disc))
		return false;

	g_rlog.attach_node(new file_log_node(&g_rlog, "stderr", 5, stderr));

	intfconf *all = new intfconf("all");
	if (!all || !all->check_startup()) {
		delete all;
		return false;
	}

	all->fill_defaults();
	m_intfconfs.add_child(all);

	groupconf *gc = (groupconf *)m_groups_node.create_child("::/0");
	if (gc)
		gc->fill_defaults();
	else
		return false;

	if (!prepare_os_components())
		return false;

	if (!m_mfa) {
		fatal().writeline("No MFA, bailing out.");
		return false;
	}

	if (!m_mfa->pre_startup())
		return false;

	if (!m_icmp) {
		m_icmp = new icmp_inet6();
	}

	if (!m_icmp) {
		fatal().writeline("No ICMPv6 handling module, bailing out.");
		return false;
	}

	if (!m_icmp->check_startup()) {
		fatal().writeline("Failed to init ICMPv6 handling module, bailing out.");
		return false;
	}

	add_static_modules();

	for (early_modules::const_iterator i = m_early_modules.begin();
			i != m_early_modules.end(); ++i) {
		load_modulex(i->c_str());
	}

	if (autoload) {
		for (static_modules::const_iterator i = m_static_modules.begin();
				i != m_static_modules.end(); i++) {
			load_modulex(i->first.c_str());
		}
	}

	if (!conffile) {
		for (int k = 0; defaultconffiles[k]; k++) {
			if (access(defaultconffiles[k], R_OK) == 0) {
				conffile = defaultconffiles[k];
				break;
			}
		}
	}

	if (!conffile) {
		fatal().writeline("No configuration file available.");
		return false;
	}

	prepare_second_components();

	if (!m_rib_handler) {
		fatal().writeline("No RIB access module, bailing out.");
		return false;
	}

	if (!m_rib_handler->check_startup()) {
		fatal().writeline("(MRD) RIB handler setup failed.");
		return false;
	}

	m_rib_handler->check_initial_interfaces();

	add_child(m_rib_handler);

	conf_parser p;

	change_state(Configuration);

	if (!p.parse(conffile)) {
		fatal().xprintf("Failed to parse configuration file "
				      "\"%s\" at line %i.\n", conffile,
				      (int32_t)p.ctx.current_line_number());

		return false;
	}

	change_state(PostConfiguration);

	if (!m_mfa->check_startup())
		return false;

	if (should_log(NORMAL)) {
		base_stream &os = log();
		show_mrd_version(os);
		os.newl();
	}

	struct sigaction act;
	memset(&act, 0, sizeof(act));

	act.sa_handler = handle_signal;

	sigaction(SIGINT, &act, 0);
	sigaction(SIGTERM, &act, 0);

	act.sa_handler = SIG_IGN;

	sigaction(SIGPIPE, &act, 0);

	act.sa_handler = 0;
	act.sa_sigaction = handle_sigsegv;
	act.sa_flags = SA_SIGINFO;

	sigaction(SIGSEGV, &act, 0);

	return true;
}

bool mrd::should_log(int level) const {
	return g_rlog.change_context(level);
}

base_stream &mrd::log() const {
	return g_rlog.current_context();
}

base_stream &mrd::fatal() const {
	should_log(FATAL);
	return log();
}

bool mrd::register_rib(rib_def *rib) {
	if (m_state > PreConfiguration)
		return false;

	if (m_rib_handler) {
		m_rib_handler->transfer_watchers(rib);
		remove_child("rib");
		delete m_rib_handler;
	}

	m_rib_handler = rib;

	add_child(m_rib_handler);

	return true;
}

void mrd::register_startup(node *n) {
	if (m_state == Running)
		n->event(StartupEvent, 0);
	else
		m_startup_nodes.push_back(n);
}

static void _check_socks(const char *tok, std::list<socket_base *> &l) {
	for (std::list<socket_base *>::const_iterator i = l.begin(); i != l.end(); i++) {
		if (g_mrd->should_log(EVERYTHING)) {
			g_mrd->log().xprintf("%s socket \"%s\" fd %i is still "
				     "open.\n", tok, (*i)->name(), (*i)->fd());
		}
	}
}

void mrd::shutdownx() {
	/// XXX block signals

	if (should_log(NORMAL))
		log().writeline("Shutting Down");

	group_list grplist = m_grplist;
	for (group_list::iterator k = grplist.begin(); k != grplist.end(); ++k)
		release_group(k->second);

	m_grplist_node.clear_childs();

	for (routers::iterator j = m_routers.begin(); j != m_routers.end(); ++j)
		j->second->shutdown();

	std::map<int, interface *> intflist = m_intflist;

	for (std::map<int, interface *>::iterator i = intflist.begin();
					i != intflist.end(); ++i)
		remove_interface(i->second);

	for (std::map<std::string, mrd_module *>::iterator k = m_modules.begin();
					k != m_modules.end(); ++k)
		k->second->shutdown();

	m_mrib.shutdown();

	m_icmp->shutdown();
	delete m_icmp;
	m_icmp = 0;

	m_rib_handler->shutdown();
	delete m_rib_handler;
	m_rib_handler = 0;

	m_mfa->shutdown();
	delete m_mfa;
	m_mfa = 0;

	m_intfconfs.clear_childs();
	m_routing_table.clear();

	m_timermgr.shutdown();

	for (std::map<std::string, mrd_module *>::iterator k = m_modules.begin();
						k != m_modules.end(); ++k) {
#ifdef MRD_NO_DYNAMIC_MODULE_LOADING
		delete k->second;
#else
		void *foo = k->second->m_dlhandle;
		delete k->second;
		if (foo)
			dlclose(foo);
#endif
	}

	m_modules.clear();

	_check_socks("Read", m_read);
	_check_socks("Write", m_write);
}

void mrd::handle_signal(int sig) {
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		g_mrd->change_state(ShuttingDown);
		break;
	case SIGSEGV:
		break;
	}
}

void mrd::change_user() {
	if (has_property("run-as")) {
		passwd *pwd;
		const char *user = get_property("run-as")->get_string();
		if (!(pwd = getpwnam(user))) {
			fatal().xprintf("(MRD) Failed to drop privileges,"
					" user %s doesn\'t exist.\n", user);
		} else {
			setuid(pwd->pw_uid);
			setgid(pwd->pw_gid);
		}
	}
}

void mrd::start() {
	change_user();

	processloop();
}

static inline int _handle_pending_socks(int res, const fd_set *fdset,
					uint32_t flags,
					const std::list<socket_base *> &l) {
	std::list<socket_base *>::const_iterator i = l.begin();
	socket_base *b;

	while (res > 0 && i != l.end()) {
		b = *i;
		++i;

		if (FD_ISSET(b->_fd, fdset)) {
			b->_hits++;
			b->callback(flags);
			res--;
		}
	}

	return res;
}

void mrd::change_state(mrd_state newstate) {
	if (m_state == newstate)
		return;

	bool call_intfs = false;

	if (m_state == Running) {
		call_intfs = true;
	} else if (newstate == Running) {
		call_intfs = true;
	}

	m_state = newstate;

	if (m_state == Running) {
		for (node_vector::iterator i = m_startup_nodes.begin();
				i != m_startup_nodes.end(); ++i) {
			(*i)->event(StartupEvent, 0);
		}
		m_startup_nodes.clear();
	}

	if (call_intfs) {
		for (interface_list::iterator i = m_intflist.begin();
				i != m_intflist.end(); ++i) {
			i->second->broadcast_change_state(newstate == Running || !i->second->up(true));
		}
	}
}

void mrd::check_enabled_interfaces(intfconf *conf) {
	for (interface_list::iterator i = m_intflist.begin();
			i != m_intflist.end(); ++i) {
		if (i->second->conf() == conf) {
			i->second->set_enabled(conf->is_enabled());
		}
	}
}

void mrd::broadcast_interface_state_changed(interface *intf) {
	if (intf->up()) {
		m_mfa->added_interface(intf);
		m_icmp->added_interface(intf);
	} else {
		m_icmp->removed_interface(intf);
		m_mfa->removed_interface(intf);
	}

	broadcast_event(mrd::InterfaceStateChanged, intf, true);
}

void mrd::processloop() {
	change_state(Running);

	int res;
	fd_set rset, wset;
	timeval tmt, *ptmt;

	m_startup = time(0);

	int _clk = sysconf(_SC_CLK_TCK);
	tms _tmp;
	clock_t a, b;
	uint32_t accum;

	while (m_state == Running) {
		if (!m_tasks.empty()) {
			a = times(&_tmp);
			do {
				task t = m_tasks.front();
				m_tasks.pop_front();
				t.target->event(t.event, t.argument);

				m_tasks_stat++;
				b = times(&_tmp);

				accum = (b - a) * 1000 / _clk;

				/* run tasks while time-spent < 10ms. */
			} while (!m_tasks.empty() && accum < 10);

			m_tasks_time_spent += accum;
		}

		rset = m_rdst;
		wset = m_wrst;
		ptmt = &tmt;

		if (m_tasks.empty()) {
			if (!m_timermgr.time_left(tmt))
				ptmt = 0;
		} else {
			tmt.tv_sec = 0;
			tmt.tv_usec = 0;
		}

		res = select(m_largestsock + 1, &rset, &wset, 0, ptmt);
		if (res < 0) {
			if (errno != EINTR) {
				if (should_log(DEBUG))
					log().perror("(MRD) select() errno");
				break;
			}
		}

		if (ptmt) {
			if (m_timermgr.handle_event())
				continue;
		}

		if (res > 0) {
			res = _handle_pending_socks(res, &rset,
						    socket_base::Read, m_read);
			_handle_pending_socks(res, &wset,
					      socket_base::Write, m_write);
		}
	}

	g_mrd->shutdownx();
}

void mrd::remove_interface(interface *intf) {
	interface_list::iterator p = m_intflist.find(intf->index());
	if (p != m_intflist.end()) {
		m_intflist.erase(p);

		m_intflist_node.remove_child(intf->name());

		/* Only output these kind of messages after startup */
		if (m_state == Running) {
			if (should_log(VERBOSE))
				log().xprintf("Removed interface %s.\n",
					      intf->name());
		}

		invalidate_intf_cache();

		for (group_list::iterator j = m_grplist.begin();
						j != m_grplist.end(); ++j)
			j->second->clear_interface_references(intf);

		bool was_up = intf->up();

		intf->set_enabled(false);
		intf->broadcast_change_state(was_up);

		m_mrib.removed_interface(intf);

		delete intf;
	} else if (should_log(EXTRADEBUG)) {
		log().xprintf("Ignored %s interface removal request,"
			      " it isn\'t instantiated.", intf->name());
	}
}

void mrd::invalidate_intf_cache() {
	memset(m_intf_cache, 0, sizeof(m_intf_cache));
}

interface *mrd::get_interface_by_name(const char *name) const {
	if (!name)
		return 0;

	for (interface_list::const_iterator i = m_intflist.begin();
					i != m_intflist.end(); ++i) {
		if (!strcmp(i->second->name(), name))
			return i->second;
	}

	return 0;
}

interface *mrd::get_loopback_interface() const {
	return get_interface_by_name(loopback_interface_name());
}

interface *mrd::found_interface(int index, const char *name, int type,
				int mtu, int flags) {
	interface *intf;
	if ((intf = get_interface_by_index(index)))
		return intf;

	bool enabled = !m_intfconfs.is_interface_disabled(name);

	intfconf *conf = (intfconf *)m_intfconfs.get_child(name);
	if (!conf) {
		conf = (intfconf *)m_intfconfs.get_child("all");
	}

	if (enabled)
		enabled = conf->is_enabled();

	// we've discovered a new interface
	intf = new interface(conf, index, name, type, mtu, flags);
	if (!intf)
		return 0;

	m_intflist.insert(std::make_pair(intf->index(), intf));

	/* XXX handle interface renames */
	m_intflist_node.add_child(intf);

	if (should_log(VERBOSE)) {
		log().xprintf("Added %s interface %s with mtu %u.\n",
			      intf->type_str(), intf->name(),
			      (uint32_t)intf->mtu());
	}

	intf->set_enabled(enabled);

	return intf;
}

void mrd::lost_interface(int intf) {
	interface_list::iterator k = m_intflist.find(intf);

	if (k != m_intflist.end()) {
		remove_interface(k->second);
	}
}

bool mrd::in_same_subnet(const in6_addr &addr) const {
	for (interface_list::const_iterator i = m_intflist.begin();
					i != m_intflist.end(); ++i) {
		if (i->second->in_same_subnet(addr))
			return true;
	}
	return false;
}

intfconf *mrd::get_interface_configuration(const char *name) {
	return (intfconf *)m_intfconfs.create_child(name);
}

intfconf *mrd::default_interface_configuration() {
	return get_interface_configuration("all");
}

groupconf *mrd::match_group_configuration(const inet6_addr &addr) const {
	return m_routing_table.match(addr);
}

groupconf *mrd::get_similiar_groupconf_node(const groupconf *gc) const {
	return m_routing_table.match(gc->id(), gc);
}

groupconf *mrd::get_group_configuration(const inet6_addr &addr) const {
	return m_routing_table.search(addr);
}

std::list<inet6_addr> mrd::configured_group_set(const char *rt) const {
	std::list<inet6_addr> addrs;

	for (group_configuration::const_iterator i =
		m_routing_table.begin(); i != m_routing_table.end(); ++i) {
		if (!rt || i->get_child(rt))
			addrs.push_back(i->id());
	}

	return addrs;
}

bool mrd::register_source_discovery(const char *name, source_discovery_origin *origin) {
	if (!origin) {
		for (source_disc::iterator i = m_source_disc.find(name);
				i != m_source_disc.end(); ++i) {
			if (i->first == name) {
				m_source_disc.erase(i);
				break;
			}
		}

		/* XXX notify all groupconf */

		return true;
	}

	if (get_source_discovery(name))
		return false;

	m_source_disc[name] = origin;

	/* XXX notify all groupconf */

	return true;
}

bool mrd::register_source_sink(source_discovery_sink *sink, bool include) {
	source_sinks::iterator i = std::find(m_source_sinks.begin(),
					m_source_sinks.end(), sink);

	if (i == m_source_sinks.end()) {
		if (!include)
			return false;
		m_source_sinks.push_back(sink);
	} else {
		if (include)
			return false;
		m_source_sinks.erase(i);
	}

	return true;
}

bool mrd::register_generic_source_sink(source_discovery_sink *sink,
				       bool include) {
	source_sinks::iterator i =
			std::find(m_all_source_sinks.begin(),
				  m_all_source_sinks.end(), sink);

	if (i == m_all_source_sinks.end()) {
		if (!include)
			return false;
		m_all_source_sinks.push_back(sink);
	} else {
		if (include)
			return false;
		m_all_source_sinks.erase(i);
	}

	return true;
}

source_discovery_origin *mrd::get_source_discovery(const char *name) const {
	source_disc::const_iterator i = m_source_disc.find(name);
	if (i == m_source_disc.end())
		return 0;

	return i->second;
}

void mrd::discovered_source(int ifindex, const inet6_addr &grpmask,
			    const inet6_addr &src,
			    source_discovery_origin *origin) {
	interface *input = get_interface_by_index(ifindex);
	if (!input || !input->up())
		return;

	for (source_sinks::iterator i = m_all_source_sinks.begin();
				i != m_all_source_sinks.end(); ++i) {
		(*i)->discovered_source(input, grpmask, src, origin);
	}

	groupconf *conf = match_group_configuration(grpmask);

	while (conf) {
		if (conf->get_source_discs().empty())
			conf = (groupconf *)conf->next_similiar_node();
		else
			break;
	}

	if (!conf)
		return;

	const groupconf::source_discs &discs = conf->get_source_discs();

	/* kinda hardcore doing string compares here.. */
	if (std::find(discs.begin(), discs.end(),
		      origin->origin_description()) == discs.end())
		return;

	if (should_log(MESSAGE_SIG)) {
		log().xprintf("Discovered Source (%{Addr}, %{Addr}) from %s.\n",
			      src, grpmask, origin->origin_description());
	}

	if (grpmask.prefixlen == 128) {
		for (source_sinks::iterator i = m_source_sinks.begin();
				i != m_source_sinks.end(); ++i) {
			(*i)->discovered_source(input, grpmask, src, origin);
		}

		group *gr = get_group_by_addr(grpmask);

		if (gr) {
			gr->discovered_source(input, src, origin);
		}
	} else {
		for (group_list::const_iterator i = m_grplist.begin();
					i != m_grplist.end(); ++i) {
			if (grpmask.matches(i->first)) {
				i->second->discovered_source(input, src, origin);
			}
		}
	}
}

void mrd::lost_source(const inet6_addr &grpmask, const inet6_addr &src,
				source_discovery_origin *origin) {
	if (grpmask.prefixlen == 128) {
		group *gr = get_group_by_addr(grpmask);

		if (gr) {
			gr->lost_source(src, origin);
		}
	} else {
		for (group_list::const_iterator i = m_grplist.begin();
					i != m_grplist.end(); ++i) {
			if (grpmask.matches(i->first)) {
				i->second->lost_source(src, origin);
			}
		}
	}
}

group *mrd::create_group(const inet6_addr &addr) {
	group *grp = get_group_by_addr(addr);
	if (!grp) {
		groupconf *conf = match_group_configuration(addr);
		if (!conf)
			return 0;

		grp = create_group(addr, conf);
	}
	return grp;
}

bool mrd::create_group(router *owner, node *caller, create_group_context *ctx) {
	if (!caller || !ctx)
		return false;

	ctx->result = get_group_by_addr(ctx->groupaddr);
	if (!ctx->result) {
		bool accept = true;

		for (create_group_acl::const_iterator i = m_create_group_acl.begin();
					accept && i != m_create_group_acl.end(); ++i) {
			accept = i->second->request_group(0, ctx->requester,
							  ctx->groupaddr, owner);
		}

		if (accept)
			ctx->result = create_group(ctx->groupaddr);
	}

	register_task(caller, CreatedGroup, ctx);

	return true;
}

group *mrd::create_group(const inet6_addr &addr, groupconf *entry) {
	group *grp = allocate_group(addr, entry);
	if (grp) {
		/* must have the group in the group list before calling
		 * router::created_group, as the nodes will try to get it */
		m_grplist.insert(std::make_pair(addr, grp));

		if (grp->check_startup()) {
			m_grplist_node.add_child(grp);

			if (should_log(NORMAL))
				log().xprintf("Created Group %{Addr}.\n", addr);

			broadcast_event(NewGroup, grp, true);
		} else {
			if (should_log(EXTRADEBUG))
				log().xprintf("Group creation failed for "
					      "%{Addr}.\n", addr);

			delete grp;
			grp = 0;
			m_grplist.erase(m_grplist.find(addr));
		}
	}
	return grp;
}

void mrd::release_group(group *grp) {
	group_list::iterator j = m_grplist.find(grp->id());
	if (j == m_grplist.end())
		return;

	broadcast_event(ReleasedGroup, grp, true);

	grp->shutdown();

	m_grplist_node.remove_child(j->first.as_string().c_str());

	delete grp;

	if (should_log(NORMAL))
		log().xprintf("Released Group %{Addr}.\n", j->first);

	m_grplist.erase(j);
}

void mrd::register_group_creation_auth(group_request_interface *gri, int prio) {
	create_group_acl::iterator i = m_create_group_acl.begin();

	if (prio <= 0) {
		while (i != m_create_group_acl.end()) {
			if (i->second == gri) {
				m_create_group_acl.erase(i);
				return;
			}
			++i;
		}
	} else {
		while (i != m_create_group_acl.end()) {
			if (prio >= i->first)
				++i;
		}

		m_create_group_acl.insert(i, std::make_pair(prio, gri));
	}
}

group *mrd::allocate_group(const inet6_addr &addr, groupconf *conf) const {
	if (should_log(EVERYTHING)) {
		base_stream &os = log();

		os.xprintf("Created group %{Addr} using source discs", addr);

		for (groupconf::source_discs::const_iterator i =
			conf->get_source_discs().begin();
			i != conf->get_source_discs().end(); ++i) {
			os.xprintf(" %s", i->c_str());
		}

		os.newl();
	}

	return new group(addr, conf);
}

group *mrd::get_group_by_addr(const inet6_addr &addr) const {
	group_list::const_iterator j = m_grplist.find(addr);
	if (j == m_grplist.end())
		return 0;
	return j->second;
}

bool mrd::register_sock(socket_base *sock, int fd, uint32_t flags) {
	if (sock->_fd != fd) {
		unregister_sock(sock);
		sock->_fd = fd;
	}

	monitor_sock(sock, flags);

	return true;
}

static inline bool _release_sock(std::list<socket_base *> &l, fd_set *fdset, socket_base *sock) {
	for (std::list<socket_base *>::iterator i = l.begin(); i != l.end(); ++i) {
		if (*i == sock) {
			FD_CLR(sock->fd(), fdset);
			l.erase(i);
			return true;
		}
	}

	return false;
}

bool mrd::unregister_sock(socket_base *sock) {
	if (sock->_fd < 0)
		return false;

	_release_sock(m_read, &m_rdst, sock);
	_release_sock(m_write, &m_wrst, sock);

	return true;
}

bool mrd::monitor_sock(socket_base *sock, uint32_t flags) {
	if (sock->fd() <= 0)
		return false;

	_release_sock(m_read, &m_rdst, sock);
	_release_sock(m_write, &m_wrst, sock);

	if (flags & socket_base::Read) {
		FD_SET(sock->fd(), &m_rdst);
		m_read.push_back(sock);
	}

	if (flags & socket_base::Write) {
		FD_SET(sock->fd(), &m_wrst);
		m_write.push_back(sock);
	}

	if (sock->fd() > m_largestsock)
		m_largestsock = sock->fd();

	return true;
}

mrd::task mrd::make_task(event_sink *target, int event, void *arg, int prio) {
	task t;
	t.target = target;
	t.event = event;
	t.prio = prio;
	t.argument = arg;
	return t;
}

void mrd::register_task(const task &t) {
	if (!t.target)
		return;
	/* XXX respect prios */
	m_tasks.push_back(t);
}

void mrd::register_task(event_sink *target, int event, void *opt, int prio) {
	register_task(make_task(target, event, opt, prio));
}

void mrd::clear_tasks(event_sink *target) {
	tasks newtasks;

	/* ``Erase in the middle of a deque invalidates all iterators that
	 * refer to the deque.'' */

	for (tasks::const_iterator i = m_tasks.begin(); i != m_tasks.end(); ++i) {
		if (i->target != target)
			newtasks.push_back(*i);
	}

	m_tasks = newtasks;
}

void mrd::interested_in_active_states(event_sink *s, bool in) {
	active_state_interest::iterator i =
		std::find(m_active_state_interest.begin(),
			  m_active_state_interest.end(), s);

	if (in) {
		if (i == m_active_state_interest.end())
			m_active_state_interest.push_back(s);
	} else if (i != m_active_state_interest.end()) {
		m_active_state_interest.erase(i);
	}
}

void mrd::state_is_active(group *g, const in6_addr &src, bool active) {
	active_state_report rep;

	rep.group_instance = g;
	rep.source_address = src;
	rep.active = active;

	for (active_state_interest::const_iterator i =
		m_active_state_interest.begin(); i != m_active_state_interest.end(); ++i) {
		(*i)->event(ActiveStateNotification, &rep);
	}
}

bool mrd::has_address(const in6_addr &addr) const {
	if (IN6_IS_ADDR_UNSPECIFIED(&addr))
		return false;

	for (interface_list::const_iterator i = m_intflist.begin();
					i != m_intflist.end(); ++i) {
		if (*i->second->linklocal() == addr)
			return true;
		if (i->second->has_global(addr))
			return true;
	}
	return false;
}

bool mrd::check_module_path(const char *name, std::string &path) {
	for (module_path::const_iterator i = m_module_path.begin();
					i != m_module_path.end(); ++i) {
		path = *i;
		path += "/";
		path += name;
		path += ".so";

		if (access(path.c_str(), F_OK) == 0)
			return true;
	}

	return false;
}

void mrd::load_early_module(const char *name) {
	m_early_modules.insert(name);
}

bool mrd::load_modulex(const char *name) {
	if (m_modules.find(name) != m_modules.end())
		return true;

	std::map<std::string, module_init_sig *>::iterator k =
		m_static_modules.find(name);

	if (k != m_static_modules.end()) {
		return add_module(name, (*k->second)(0, this));
	}

#ifdef MRD_NO_DYNAMIC_MODULE_LOADING
	return false;
#else
	std::string path;

	if (!check_module_path(name, path)) {
		if (should_log(WARNING))
			log().xprintf("(MRD) Failed to load module %s.\n",
				      name);
		return false;
	}

	/* There will be a FS limit so don't worry about the size
	   - Thomas Preud'homme, 11.05.2010, fix for GNU HURD */
	void *foo = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);

	module_init_sig *load = 0;
	if (foo) {
		std::string initfunsym = "mrd_module_init_";
		initfunsym += name;

		load = (module_init_sig *)dlsym(foo, initfunsym.c_str());
	}

	if (!foo || !load) {
		if (should_log(WARNING))
			log().xprintf("(MRD) Failed to load module %s (%s).\n",
				      name, dlerror());
		if (foo)
			dlclose(foo);
		return false;
	}

	mrd_module *mod = (*load)(foo, this);
	if (!mod) {
		if (should_log(WARNING))
			log().xprintf("(MRD) Failed to init module %s.\n",
				      name);
		return false;
	}

	return add_module(name, mod);
#endif
}

bool mrd::add_module(const char *name, mrd_module *mod) {
	if (!mod->check_startup()) {
		if (should_log(WARNING))
			log().xprintf("(MRD) Failed to init module %s.\n",
				      name);
		delete mod;
		return false;
	}

	std::map<std::string, mrd_module *> modls = m_modules;

	for (std::map<std::string, mrd_module *>::iterator k = modls.begin();
							k != modls.end(); ++k) {
		mod->module_loaded(k->first.c_str(), k->second);
		k->second->module_loaded(name, mod);
	}

	m_modules[name] = mod;

	return true;
}

bool mrd::remove_module(const char *n) {
	std::map<std::string, mrd_module *>::iterator i = m_modules.find(n);

	if (i == m_modules.end())
		return false;

	return remove_module(i->second);
}

bool mrd::remove_module(mrd_module *mod) {
	std::map<std::string, mrd_module *>::iterator i;
	for (i = m_modules.begin(); i != m_modules.end(); ++i) {
		if (i->second == mod)
			break;
	}
	if (i == m_modules.end())
		return false;

#ifndef MRD_NO_DYNAMIC_MODULE_LOADING
	void *foo = i->second->m_dlhandle;
#endif

	i->second->shutdown();
	delete i->second;
	m_modules.erase(i);

#ifndef MRD_NO_DYNAMIC_MODULE_LOADING
	if (foo)
		dlclose(foo);
#endif

	return true;
}

bool mrd::set_property(const char *what, const char *value) {
	if (!strcmp(what, "module-path")) {
		m_module_path.clear();
		m_module_path.push_back(value);

		return true;
	} else if (!strcmp(what, "run-as")) {
		return set_property_inst(what, property_def::VAL_STRING, value);
	}

	return node::set_property(what, value);
}

bool mrd::increment_property(const char *what, const char *value) {
	if (!strcmp(what, "modules")) {
		return load_modulex(value);
	} else if (!strcmp(what, "module-path")) {
		m_module_path.push_back(value);
		return true;
	}

	return false;
}

bool mrd::call_method(int id, base_stream &out,
		      const std::vector<std::string> &args) {
	switch (id) {
	case method_shutdown:
		return shutdown(out, args);
	case method_version:
		return show_version(out, args);
	case method_timers:
		return show_timers(out, args);
	case method_rpf:
		return show_rpf(out, args);
	case method_load_module:
		return load_module(out, args);
	case method_unload_module:
		return unload_module(out, args);
	case method_unicast_regs:
		return unicast_regs(out, args);
	case method_socket_regs:
		return socket_regs(out, args);
	case method_show_info:
		return show_info(out, args);
	case method_conf:
		return show_conf(out, args);
	case method_show_commands:
		return show_commands(out, args);
	case method_show:
		return show(out, args);
	case method_dump_tree:
		dump_node_tree(out, g_mrd);
		return true;
#ifdef CRASH_COMMAND
	case method_crash:
		*((int *)0xdeadbeef) = 0xb00;
		/* won't reach here */
		return true;
#endif
	}

	return node::call_method(id, out, args);
}

void mrd::event(int type, void *arg) {
	if (type == RemoveGroup) {
		release_group((group *)arg);
	} else {
		node::event(type, arg);
	}
}

bool mrd::show_timers(base_stream &out, const std::vector<std::string> &args) {
	return m_timermgr.output_info(out, !args.empty() && args[0] == "extended");
}

bool mrd::show_rpf(base_stream &out, const std::vector<std::string> &args) {
	if (args.empty()) {
		out.writeline("Method usage: show rpf <destination>");
	} else {
		inet6_addr addr;

		if (!addr.set(args[0])) {
			out.writeline("Argument must be destination address.");
		} else {
			bool debug = false;

			inet6_addr grpaddr;
			if (args.size() > 1) {
				if (args[1] == "debug")
					debug = true;
				else
					grpaddr.set(args[1]);
			}

			base_stream &os =
				out.xprintf("RPF information for %{Addr}", addr);
			if (!grpaddr.is_any())
				os.xprintf(" (%{Addr})", grpaddr);
			os.newl();
			out.inc_level();

			inet6_addr nh;

			timeval ts, te;

			gettimeofday(&ts, 0);
			const mrib_def::prefix *p = mrib().resolve_nexthop(addr, grpaddr, nh);
			gettimeofday(&te, 0);

			if (p) {
				out.xprintf("Record prefix: %{Addr}\n", p->get_prefix());
				out.xprintf("Origin: %s\n", p->owner->description());

				out.inc_level();
				p->owner->output_prefix_info(out, *p);
				out.dec_level();

				out.xprintf("Nexthop: %{Addr}\n", nh);
				if (p->intf) {
					out.xprintf("Outgoing interface: %s\n",
						    p->intf->name());
				} else {
					out.writeline("No available path.");
				}

				if (debug) {
					uint64_t diff = (te.tv_sec - ts.tv_sec) * 1000000;

					if (te.tv_usec > ts.tv_usec)
						diff += te.tv_usec - ts.tv_usec;
					else
						diff += (1000000 + te.tv_usec - ts.tv_usec);

					out.printf("Took: %lluus", diff).newl();

					out.inc_level();

					int i;
					out.write("Target: ");
					for (i = 0; i < 128; i++) {
						if (i == p->get_prefix().prefixlen)
							out.write(" ");
						out.write(pnode_symbol_at(addr, i) ? "1" : "0");
					}
					out.newl();

					out.write("Prefix: ");
					for (i = 0; i < 128; i++) {
						if (i == p->get_prefix().prefixlen)
							out.write(" ");
						out.write(pnode_symbol_at(p->get_prefix(), i) ? "1" : "0");
					}
					out.newl();

					out.dec_level();
				}
			} else {
				out.writeline("No information available.");
			}

			out.dec_level();
		}
	}

	return true;
}

bool mrd::shutdown(base_stream &out, const std::vector<std::string> &ctx) {
	if (m_state != Running)
		return false;

	change_state(ShuttingDown);

	return true;
}

bool mrd::show_mrd_version(base_stream &os) const {
	utsname name;

	if (uname(&name) == 0) {
		os.xprintf("This is `%s\' running %s the IPv6 Multicast "
			   "Routing Daemon, in %s %s", name.nodename,
			   VersionInfo, name.sysname, name.release);
		return true;
	}

	return false;
}

bool mrd::show_version(base_stream &out, const std::vector<std::string> &ctx) {
	bool res = show_mrd_version(out);

	out.newl();

	return res;
}

bool mrd::load_module(base_stream &out, const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		load_modulex(i->c_str());
	}

	return true;
}

bool mrd::unload_module(base_stream &out, const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		remove_module(i->c_str());
	}

	return true;

}

bool mrd::unicast_regs(base_stream &out, const std::vector<std::string> &ctx) {
	return m_rib_handler->dump_info(out);
}

static inline void _dump_socks(base_stream &_out, std::list<socket_base *> &l) {
	for (std::list<socket_base *>::const_iterator i = l.begin(); i != l.end(); i++) {
		_out.printf("\"%s\" fd %i hits %llu", (*i)->name(), (*i)->fd(),
			    (*i)->hits()).newl();
	}
}

bool mrd::socket_regs(base_stream &out, const std::vector<std::string> &ctx) {
	out.writeline("Sockets");
	out.inc_level();

	out.writeline("Read");
	out.inc_level();

	if (!m_read.empty()) {
		_dump_socks(out, m_read);
	} else {
		out.writeline("(None)");
	}

	out.dec_level();

	if (!m_write.empty()) {
		out.writeline("Write");

		out.inc_level();
		_dump_socks(out, m_write);
		out.dec_level();
	}

	out.dec_level();

	return true;
}

void mrd::show_base_info(base_stream &out) const {
	out.xprintf("Version: %s\n", VersionInfo);
	out.xprintf("Build date: %s\n", BuildDate);
}

bool mrd::show_info(base_stream &out, const std::vector<std::string> &ctx) {
	show_base_info(out);

	out.xprintf("Uptime: %{duration}\n", time_duration((time(0) - m_startup) * 1000));
	out.xprintf("Performed tasks: %u (spent %llu ms)\n", m_tasks_stat, m_tasks_time_spent);
	out.xprintf("Registered sockets: %u reading, %u writing\n",
		(uint32_t)m_read.size(), (uint32_t)m_write.size());
	out.xprintf("MRIB prefix count: %u\n", mrib().registry_prefix_count());
	out.xprintf("Interface count: %u\n", (uint32_t)m_intflist.size());
	out.xprintf("Group state count: %u\n", (uint32_t)m_grplist.size());

	return true;
}

bool mrd::show_conf(base_stream &out, const std::vector<std::string> &ctx) {
	show_conf_node(out, this, true);

	return true;
}

int mrd::show_conf_node(base_stream &_out, node *n, bool print) const {
	if (!n)
		return 0;

	std::vector<const char *> props, childs;

	const properties &nodeprops = n->get_properties();

	for (properties::const_iterator i = nodeprops.begin();
			i != nodeprops.end(); ++i) {
		if (i->second.is_property())
			props.push_back(i->first.c_str());
		else if (i->second.is_child())
			childs.push_back(i->first.c_str());
	}

	int count = 0;

	bool shouldprint = false;

	if (print) {
		shouldprint = show_conf_node(_out, n, false) > 0;
	}

	if (shouldprint && n != this) {
		_out.xprintf("%s {\n", n->name());
		_out.inc_level();
	}

	for (std::vector<const char *>::const_iterator i =
			props.begin(); i != props.end(); ++i) {
		const property_def *prop = n->get_property(*i);
		if (prop && !prop->is_readonly() && !prop->is_default()) {
			if (shouldprint) {
				base_stream &os = _out.xprintf("%s = ", *i);
				prop->output_value(os);
				os.writeline(";");
			}
			count++;
		}
	}

	for (std::vector<const char *>::const_iterator i =
				childs.begin(); i != childs.end(); ++i) {
		count += show_conf_node(_out, n->get_child(*i), print);
	}

	if (shouldprint && n != this) {
		_out.dec_level();
		_out.writeline("}");
	}

	return count;
}

bool mrd::show_commands(base_stream &out, const std::vector<std::string> &args) {
	if (!args.empty())
		return false;

	dump_commands(out, this, std::string());

	return true;
}

void mrd::dump_commands(base_stream &_out, const node *n,
			const std::string &_path) const {
	std::string path = _path;

	if (n->parent()) {
		path += n->name();
		path += " ";
	}

	const properties &nodeprops = n->get_properties();

	for (properties::const_iterator i = nodeprops.begin();
			i != nodeprops.end(); ++i) {
		if (i->second.is_method() && !(i->second.flags() & property_def::DEFAULT_VALUE)) {
			if (i->second.is_readonly())
				_out.write("show ");
			_out.xprintf("%s%s\n", path.c_str(), i->first.c_str());
			if (i->second.get_method_info()->flags & property_def::NEGATE)
				_out.xprintf("%sno %s\n", path.c_str(), i->first.c_str());
		}
	}

	for (properties::const_iterator i = nodeprops.begin();
			i != nodeprops.end(); ++i) {
		if (i->second.is_child()) {
			dump_commands(_out, i->second.get_node(), path);
		}
	}
}

void mrd::dump_node_tree(base_stream &s, node *n) const {
	std::vector<node *> visited;
	return dump_node_tree(s, n, visited);
}

void mrd::dump_node_tree(base_stream &s, node *n, std::vector<node *> &visited) const {
	for (properties::const_iterator i = n->get_properties().begin();
			i != n->get_properties().end(); ++i) {
		if (i->second.is_child()) {
			s.write(i->first.c_str());
			node *ch = i->second.get_node();
			if (std::find(visited.begin(), visited.end(), ch) != visited.end()) {
				s.writeline(" (dup)");
				continue;
			}

			s.newl();

			visited.push_back(ch);
			s.inc_level();
			dump_node_tree(s, ch, visited);
			s.dec_level();
		}
	}
}

void mrd::group_configuration::clear() {
	iterator i;

	while ((i = begin()) != end()) {
		groupconf *n = &(*i);

		remove(n);

		delete n;
	}
}

groupconf *mrd::group_configuration::create_child(const inet6_addr &addr) {
	groupconf *conf = new groupconf(addr);

	if (!conf || !conf->check_startup()) {
		delete conf;
		return 0;
	}

	insert(conf);

	return conf;
}

groupconf *mrd::group_configuration::match(const inet6_addr &addr,
					   const groupconf *prev) const {
	if (prev) {
		return get_parent_node(prev);
	}

	return longest_match(addr);
}

mrd::groups_node::groups_node(node *p)
	: node(p, "groups") {
}

node *mrd::groups_node::get_child(const char *name) const {
	inet6_addr addr;

	if (!addr.set(name))
		return 0;

	return node::get_child(addr.as_string().c_str());
}

node *mrd::groups_node::create_child(const char *name) {
	inet6_addr addr;

	if (!addr.set(name))
		return 0;

	groupconf *gc = g_mrd->m_routing_table.create_child(addr);

	if (gc)
		add_child(gc);

	return gc;
}

mrd_module::mrd_module(mrd *m, void *dlhandle)
	: m_dlhandle(dlhandle), m_mrd(m) {
}

mrd_module::~mrd_module() {
}

uint32_t
mrd::get_randu32()
{
	return rand() * 12345;
}

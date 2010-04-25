/*
 * Multicast Routing Daemon (MRD)
 *   bgp.cpp
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
#include <mrd/rib.h>
#include <mrd/interface.h>
#include <mrd/support/objpool.h>

#include <mrdpriv/bgp/def.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/times.h> /* times */
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <map>

#include <limits.h>

class bgp_module;

static const bgp_community no_export(65535, 65281);
static const bgp_community no_advertise(65535, 65282);

/* default eBGP weight and local-pref in IOS, Zebra, etc */
static const uint32_t DEFAULT_BGP_DISTANCE = 20;
static const uint32_t DEFAULT_LOCAL_PREF = 100;

static inline const char *stream_type_format_parameter(const bgp_community &) {
	return "{community}";
}

static inline void stream_push_formated_type(base_stream &os,
					     const bgp_community &c) {
	os.xprintf("%u:%u", (uint32_t)c.first, (uint32_t)c.second);
}

enum {
	BGP_OPEN		= 1,
	BGP_UPDATE		= 2,
	BGP_NOTIFICATION	= 3,
	BGP_KEEPALIVE		= 4
};

static const char *error_messages[] = {
	"Message Header Error",
	"Open Message Error",
	"Update Message Error",
	"Hold Timer Expired",
	"Finite State Machine Error",
	"Cease"
};

enum {
	MessageHeaderError = 1,
	OpenMessageError,
	UpdateMessageError,
	HoldTimerExpired,
	FiniteStateMachineError,
	Cease
};

static const char *suberror_messages[][11] = {
	{ "Connection Not Synchronized",
	  "Bad Message Length",
	  "Bad Message Type" },
	{ "Unsupported Version Number",
	  "Bad Peer AS",
	  "Bad BGP Identifier",
	  "Unsupported Optional Parameter",
	  "Authentication Failure",
	  "Unacceptable HoldTime",
	  "Unsupported Capability" },
	{ "Malformed Attribute List",
	  "Unrecognized Well-Known Attribute",
	  "Missing Well-Known Attribute",
	  "Attribute Flags Error",
	  "Attribute Length Error",
	  "Invalid Origin Attribute",
	  "AS Routing Loop",
	  "Invalid Next Hop Attribute",
	  "Optional Attribute Error",
	  "Invalid Network Field",
	  "Malformed AS_Path" }
};

enum {
	bgp_neigh_method_filter = 10000,
	bgp_neigh_method_route_map,
	bgp_neigh_method_activate,
	bgp_neigh_method_reconnect,
	bgp_neigh_method_debug,
	bgp_neigh_method_alias
};

static const method_info bgp_neigh_methods[] = {
	{ "filter", 0, bgp_neigh_method_filter, false, property_def::NEGATE },
	{ "route-map", 0, bgp_neigh_method_route_map, false, property_def::NEGATE },
	{ "activate", "Activates the peering to the specified neighbor",
		bgp_neigh_method_activate, false, property_def::NEGATE },
	{ "reconnect", "Forces a reconnect to the specified neighbor",
		bgp_neigh_method_reconnect, false, 0 },
	{ "debug", 0, bgp_neigh_method_debug, true, 0 },
	{ "alias", "Sets a name alias for the neighbor",
		bgp_neigh_method_alias, false, 0 },
	{ 0 }
};

enum {
	bgp_acl_method_prefix = 11000,
};

static const method_info bgp_acl_methods[] = {
	{ "prefix", "Adds a new ACL prefix entry",
		bgp_acl_method_prefix, false, property_def::NEGATE },
	{ 0 }
};

enum {
	bgp_rmap_method_match = 12000,
	bgp_rmap_method_set,
	bgp_rmap_method_prepend_aspath
};

static const method_info bgp_rmap_methods[] = {
	{ "match", 0, bgp_rmap_method_match, false, property_def::NEGATE },
	{ "set", 0, bgp_rmap_method_set, false, property_def::NEGATE },
	{ "prepend-aspath", 0, bgp_rmap_method_prepend_aspath, false, property_def::NEGATE },
	{ 0 }
};

enum {
	AllCount = 0,
	KeepaliveCount,
	OpenCount,
	UpdateCount,
	NotificationCount,
	MessageCount
};

enum {
	RX = 0,
	TX,
	Bad
};

static const char *stats_descriptions[] = {
	"All",
	"Keepalive",
	"Open",
	"Update",
	"Notification",
};

static inline bool valid_error(uint8_t error, uint8_t suberror) {
	if (error < 1 || error > 6)
		return false;
	if (error == 1)
		return suberror >= 1 && suberror <= 3;
	else if (error == 2)
		return suberror >= 1 && suberror <= 7;
	else if (error == 3)
		return suberror >= 1 && suberror <= 11;
	return true;
}

class bgp_neighbor : public node, public mrib_origin, public rib_watcher_base {
public:
	bgp_neighbor(node *, const inet6_addr &);
	~bgp_neighbor();

	bool check_startup();
	void shutdown();

	const char *description() const { return "MBGP"; }

	uint16_t as_number() const { return get_property_unsigned("peer-as"); }

	enum bgp_mode {
		EBGP,
		IBGP
	};

	enum {
		WorkPending = 'W'
	};

	bgp_mode mode() const { return strcasecmp(get_property_string("mode"),
					"EBGP") ? IBGP : EBGP; }
	uint32_t holdtime() const { return get_property_unsigned("holdtime"); }

	void return_prefix(mrib_def::prefix *);

	interface *peer_interface() const;

	bool active() const { return currstate == ESTABLISHED; }
	void activate_with(int);

	struct bgp_prefix : mrib_def::prefix {
		bgp_prefix(bgp_neighbor *owner, const bgp_as_path &_aspath)
			: mrib_def::prefix(owner, DEFAULT_BGP_DISTANCE),
			  as_path(_aspath) {
			should_export = should_advertise = true;
			localpref = DEFAULT_LOCAL_PREF;
		}

		uint8_t bgp_origin;
		bgp_as_path as_path;
		bool should_export, should_advertise;
		uint32_t localpref;
	};

	void prefix_added(const inet6_addr &, mrib_def::metric_def, const mrib_def::prefix &);
	void prefix_lost(const inet6_addr &, mrib_def::metric_def, const mrib_def::prefix &);

	bool set_property(const char *, const char *);
	bool call_method(int id, base_stream &out,
			 const std::vector<std::string> &);
	bool negate_method(int id, base_stream &out,
			   const std::vector<std::string> &);
	bool output_info(base_stream &ctx, const std::vector<std::string> &) const;
	bool output_info(base_stream &ctx, bool) const;

	void output_prefix_info(base_stream &, const mrib_def::prefix &) const;

	bool send_message(const bgp_message &);

	bool send_update(const bgp_update_message &);
	bool send_open(const bgp_open_message &);

	enum state {
		INACTIVE,
		IDLE,
		CONNECT,
		ACTIVE,
		OPEN_SENT,
		OPEN_CONFIRM,
		ESTABLISHED
	};

	void change_state_to(state);

	bool new_connection_from(int sock);

	base_stream &log() const;

private:
	void data_available(uint32_t);
	void event(int, void *);
	void timed_out();

	void start_connect();
	void connected();
	void finish_connect_setup();

	bool handle_open(bgp_open_message &);
	void build_update_work(bgp_update_message &);
	bool handle_notify(bgp_notification_message &);
	void handle_keepalive();

	bool encode_msg(const bgp_message &);
	bool trigger_open();
	void send_keepalive();
	void send_notification(uint8_t, uint8_t = 0);
	void handle_localholdtime();

	void route_changed(uint32_t);

	void install_prefix(const inet6_addr &prefix, uint8_t origin,
			    const in6_addr &nh, const bgp_as_path &aspath,
			    const bgp_communities &communities);

	message_stats_node m_stats;

	property_def *AS;
	std::string alias;

	inet6_addr peeraddr;
	/* to avoid tons of inet6_addr -> string conversions */
	std::string peeraddr_s;

	socket0<bgp_neighbor> sock;
	tval lastconnect;
	tval lastka, lastsentka;

	state currstate;

	bool work_pending;

	enum {
		InstallPrefix = 1,
		RemovePrefix = 2
	};

	struct work_token {
		int action;
		uint8_t origin;
		inet6_addr prefix;
		in6_addr nexthop;
		bgp_as_path as_path;
		bgp_communities communities;
	};

	typedef std::deque<work_token> work_buffer_def;
	work_buffer_def work_buffer;
	uint32_t max_work_buffer_size;

	static const char *_state_name(state);

	timer<bgp_neighbor> localholdtimer, holdtimer;

	encoding_buffer ibuf, obuf;

	void trigger_send_peer();

	int prefixcount;

	std::map<int, std::string> input_filter, output_filter,
				   input_rmap, output_rmap;

	bool run_filter(const std::map<int, std::string> &, const inet6_addr &) const;
	bool run_route_map(const std::map<int, std::string> &,
			   const inet6_addr &, in6_addr &,
			   bgp_as_path &, mrib_def::metric_def &metric,
			   uint32_t &localpref) const;

	bool conf_filter_rmap(bool filter, const std::vector<std::string> &);

	bool reconnect();
};

class bgp_neighbors : public node {
public:
	bgp_neighbors(node *);

	const char *description() const { return "BGP neighbors"; }

	node *get_child(const char *) const;
	node *create_child(const char *);

	bgp_neighbor *get_neigh(const in6_addr &) const;

	void remove_all();

	bool has_neigh(bgp_neighbor *n) const;

	bgp_neighbor *get_alias(const char *) const;
	void add_alias(const char *, bgp_neighbor *);
	void remove_alias(const char *);

	bool output_info(base_stream &ctx, const std::vector<std::string> &) const;

private:
	typedef std::map<in6_addr, bgp_neighbor *> neighbors;
	neighbors m_neighs;
	typedef std::map<std::string, bgp_neighbor *> aliases;
	aliases m_aliases;
};

class bgp_access_lists;
class bgp_route_maps;

class bgp_acl : public node {
public:
	bgp_acl(bgp_access_lists *, const char *);

	bool check_startup();

	bool call_method(int, base_stream &, const std::vector<std::string> &);
	bool negate_method(int, base_stream &, const std::vector<std::string> &);

	bool prefix(const std::vector<std::string> &);
	bool no_prefix(const std::vector<std::string> &);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

	bool accepts(const inet6_addr &) const;

	struct entry {
		bool mode;
		inet6_addr prefix;
		int ge, le;
	};

	typedef std::map<int, entry> entries;
	entries m_entries;
};

class bgp_access_lists : public node {
public:
	bgp_access_lists(node *);

	const char *description() const { return "Access lists"; }

	node *create_child(const char *);

	bool output_info(base_stream &, const std::vector<std::string> &) const;
};

class bgp_rmap : public node {
public:
	bgp_rmap(bgp_route_maps *, const char *);

	bool check_startup();

	bool call_method(int, base_stream &, const std::vector<std::string> &);
	bool negate_method(int, base_stream &, const std::vector<std::string> &);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

	bool applies(const inet6_addr &, in6_addr &,
		     bgp_as_path &, mrib_def::metric_def &, uint32_t &) const;

	std::string m_match_filter;

	enum action_type {
		PREPEND_ASPATH = 1,
		LOCAL_PREF,
		METRIC,
		COMMUNITY,
	};

	struct action {
		action_type type;
		union {
			uint16_t as;
			int metric;
			struct {
				uint16_t first, second;
			} c;
		} v;
	};

	typedef std::vector<action> actions;
	actions m_actions;
};

class bgp_route_maps : public node {
public:
	bgp_route_maps(node *);

	const char *description() const { return "Route maps"; }

	node *create_child(const char *);

	bool output_info(base_stream &, const std::vector<std::string> &) const;
};

class bgp_module : public mrd_module, public node {
public:
	bgp_module(mrd *m, void *dlh);

	const char *description() const;

	bool check_startup();
	void shutdown();

	void listen_for_neighs();

	uint16_t as_number() const { return get_property_unsigned("router-as"); }
	uint32_t id() const { return get_property_unsigned("id"); }

	bool set_property(const char *, const char *);

	bool output_info(base_stream &ctx, const std::vector<std::string> &) const;

	bool has_neighbor(bgp_neighbor *) const;

	bgp_acl *get_acl(const char *) const;
	bgp_rmap *get_rmap(const char *) const;

	bgp_neighbors &neighs() { return m_neighs; }

	base_stream &log() const;

	objpool<bgp_neighbor::bgp_prefix> prefix_pool;

private:
	void connection_pending(uint32_t);

	bgp_neighbors m_neighs;
	bgp_access_lists m_acls;
	bgp_route_maps m_rmaps;

	socket0<bgp_module> sock;
};

module_entry(bgp, bgp_module);

static bgp_module *bgp = 0;

static inline bool _parse_asnumber(const char *value, uint16_t &res) {
	char *end;
	uint32_t val = strtoul(value, &end, 10);
	if (*end || val > 0xffff)
		return false;
	res = (val & 0xffff);
	return true;
}

static bool _parse_int(const std::string &in, int &out) {
	char *end;
	out = strtol(in.c_str(), &end, 10);
	return !*end;
}

static bool _parse_community(const std::string &in, bgp_community &out) {
	std::string tmp = in;

	int k = tmp.find(':');
	if (k >= (int)tmp.size())
		return false;

	std::string p1(in.begin(), in.begin() + k);
	if (!_parse_asnumber(p1.c_str(), out.first))
		return false;
	std::string p2(in.begin() + k + 1, in.end());
	if (!_parse_asnumber(p2.c_str(), out.second))
		return false;

	return true;
}

bgp_neighbors::bgp_neighbors(node *parent)
	: node(parent, "neighbor") {
}

node *bgp_neighbors::get_child(const char *name) const {
	aliases::const_iterator i = m_aliases.find(name);
	if (i != m_aliases.end())
		return i->second;
	inet6_addr addr;
	if (!addr.set(name) || addr.prefixlen < 128)
		return 0;
	return get_neigh(addr);
}

node *bgp_neighbors::create_child(const char *name) {
	inet6_addr addr;
	if (!addr.set(name))
		return 0;
	if (addr.prefixlen < 128)
		return 0;

	bgp_neighbor *neigh = new bgp_neighbor(this, addr);
	if (!neigh || !neigh->check_startup()) {
		delete neigh;
		return 0;
	}

	m_neighs[addr] = neigh;

	add_child(neigh);

	bgp->listen_for_neighs();

	return neigh;
}

void bgp_neighbors::remove_all() {
	for (neighbors::iterator i = m_neighs.begin(); i != m_neighs.end(); ++i) {
		i->second->shutdown();
		delete i->second;
	}
	m_neighs.clear();
	m_aliases.clear();

	clear_childs();
}

bgp_neighbor *bgp_neighbors::get_neigh(const in6_addr &addr) const {
	neighbors::const_iterator i = m_neighs.find(addr);
	if (i == m_neighs.end())
		return 0;
	return i->second;
}

bool bgp_neighbors::has_neigh(bgp_neighbor *n) const {
	for (neighbors::const_iterator i = m_neighs.begin(); i != m_neighs.end(); ++i) {
		if (i->second == n)
			return true;
	}

	return false;
}

bool bgp_neighbors::output_info(base_stream &ctx, const std::vector<std::string> &args) const {
	if (m_neighs.empty()) {
		ctx.writeline("(None)");
	} else {
		for (neighbors::const_iterator i = m_neighs.begin(); i != m_neighs.end(); ++i) {
			i->second->output_info(ctx, args);
		}
	}

	return true;
}

bgp_neighbor *bgp_neighbors::get_alias(const char *name) const {
	aliases::const_iterator i = m_aliases.find(name);
	if (i == m_aliases.end())
		return 0;
	return i->second;
}

void bgp_neighbors::add_alias(const char *name, bgp_neighbor *neigh) {
	m_aliases[name] = neigh;

	add_child(neigh, false, name);
}

void bgp_neighbors::remove_alias(const char *name) {
	aliases::iterator i = m_aliases.find(name);

	if (i != m_aliases.end()) {
		m_aliases.erase(i);

		remove_child(name);
	}
}

bgp_module::bgp_module(mrd *m, void *dlh)
	: mrd_module(m, dlh), node(m, "bgp"), prefix_pool(256),
	  m_neighs(this), m_acls(this), m_rmaps(this),
	  sock("bgp listen", this, std::mem_fun(&bgp_module::connection_pending)) {

	bgp = this;

	add_child(&m_neighs);
	add_child(&m_acls);
	add_child(&m_rmaps);

	instantiate_property_u("router-as", 0);
	/* XXX */
	instantiate_property_u("id", 0xdeadbeef);

	instantiate_property_a("local-bind", inet6_addr::any());
}

const char *bgp_module::description() const {
	return "Border Gateway Protocol (Multicast SAFI)";
}

bool bgp_module::check_startup() {
	if (!node::check_startup())
		return false;

	if (!m_neighs.check_startup())
		return false;

	if (!m_acls.check_startup())
		return false;

	if (!m_rmaps.check_startup())
		return false;

	m_mrd->add_child(this);

	return has_property("router-as") && has_property("id") && has_property("local-bind");
}

void bgp_module::listen_for_neighs() {
	if (sock.fd() > 0)
		return;

	int s = socket(PF_INET6, SOCK_STREAM, 0);
	if (s < 0)
		return;

	sockaddr_in6 localaddr = get_property_address("local-bind").as_sockaddr();
	localaddr.sin6_port = htons(179);

	int on = 1;

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(s, (sockaddr *)&localaddr, sizeof(localaddr)) < 0
		|| listen(s, 5) < 0) {
		close(s);
		return;
	}

	sock.register_fd(s);
}

void bgp_module::shutdown() {
	m_neighs.remove_all();

	if (sock.fd() > 0) {
		::shutdown(sock.fd(), SHUT_RDWR);
		sock.unregister();
	}

	m_mrd->remove_child("bgp");
}

void bgp_module::connection_pending(uint32_t) {
	sockaddr_in6 src;
	socklen_t socklen = sizeof(src);

	int newclsock = accept(sock.fd(), (sockaddr *)&src, &socklen);
	if (newclsock < 0) {
		if (should_log(DEBUG))
			log().perror("failed during accept in connection_pending");
		return;
	}

	if (should_log(EXTRADEBUG))
		log().xprintf("Accepted new connection from %{addr}, fd %i.\n",
			      src.sin6_addr, newclsock);

	bgp_neighbor *neigh = m_neighs.get_neigh(src.sin6_addr);
	if (neigh) {
		if (neigh->new_connection_from(newclsock))
			return;
	} else if (should_log(NORMAL)) {
		log().xprintf("%{addr} has no configuration, ignoring.\n",
			      src.sin6_addr);
	}

	close(newclsock);
}

bool bgp_module::has_neighbor(bgp_neighbor *neigh) const {
	return m_neighs.has_neigh(neigh);
}

bgp_acl *bgp_module::get_acl(const char *name) const {
	return (bgp_acl *)m_acls.get_child(name);
}

bgp_rmap *bgp_module::get_rmap(const char *name) const {
	return (bgp_rmap *)m_rmaps.get_child(name);
}

bool bgp_module::set_property(const char *key, const char *value) {
	if (!strcmp(key, "router-as")) {
		uint16_t asnumber;
		if (!_parse_asnumber(value, asnumber))
			return false;
	}
	return node::set_property(key, value);
}

bool bgp_module::output_info(base_stream &ctx, const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	ctx.writeline("BGP");

	ctx.inc_level();

	ctx.xprintf("AS: %u\n", (uint32_t)as_number());

	ctx.writeline("Neighbors:");

	ctx.inc_level();

	m_neighs.output_info(ctx, args);

	ctx.dec_level();

	ctx.dec_level();

	return true;
}

bgp_neighbor::bgp_neighbor(node *parent, const inet6_addr &addr)
	: node(parent, addr.as_string().c_str()),
		m_stats(this, MessageCount, stats_descriptions), peeraddr(addr),
		sock("bgp neighbor conn", this, std::mem_fun(&bgp_neighbor::data_available)),
		localholdtimer("bgp local holdtime", this,
				std::mem_fun(&bgp_neighbor::handle_localholdtime), 60000, true),
		holdtimer("bgp holdtimer", this, std::mem_fun(&bgp_neighbor::timed_out)),
		ibuf(4096), obuf(4096) {

	peeraddr_s = peeraddr.as_string();

	prefixcount = 0;

	AS = instantiate_property_u("peer-as", 0);

	instantiate_property_s("mode", "EBGP");
	instantiate_property_u("holdtime", 180);

	currstate = INACTIVE;

	work_pending = false;
	max_work_buffer_size = 0;

	g_mrd->register_startup(this);
}

bgp_neighbor::~bgp_neighbor() {
}

bool bgp_neighbor::check_startup() {
	if (!node::check_startup())
		return false;

	if (!m_stats.setup())
		return false;

	m_stats.disable_counter(AllCount, TX);

	if (!ibuf.check_startup() || !obuf.check_startup())
		return false;

	if (!AS)
		return false;

	import_methods(bgp_neigh_methods);

	localholdtimer.start();

	return true;
}

void bgp_neighbor::route_changed(uint32_t which) {
	if (currstate < IDLE)
		return;

	if (which & DEV) {
		if (currstate > IDLE && should_log(DEBUG))
			log().writeline("Route towards peer changed, reconnecting.");

		change_state_to(IDLE);
		start_connect();
	}
}

void bgp_neighbor::shutdown() {
	change_state_to(INACTIVE);

	if (!alias.empty())
		bgp->neighs().remove_alias(alias.c_str());
}

void bgp_neighbor::activate_with(int newsock) {
	sock.register_fd(newsock);

	if (should_log(VERBOSE))
		log().writeline("Peer Connected.");

	finish_connect_setup();
}

void bgp_neighbor::return_prefix(mrib_def::prefix *p) {
	bgp->prefix_pool.return_obj((bgp_prefix *)p);
}

interface *bgp_neighbor::peer_interface() const {
	return valid ? g_mrd->get_interface_by_index(dev) : 0;
}

void bgp_neighbor::finish_connect_setup() {
	lastconnect = tval::now();

	change_state_to(ACTIVE);
}

void bgp_neighbor::start_connect() {
	if (sock.fd() > 0)
		return;

	localholdtimer.start_or_update(60000, true);

	int s = socket(PF_INET6, SOCK_STREAM, 0);
	if (s > 0) {
		int flags = fcntl(s, F_GETFL, 0);
		if (fcntl(s, F_SETFL, flags | O_NONBLOCK) != 0) {
			close(s);
			return;
		}

		sockaddr_in6 peer = peeraddr.as_sockaddr();
		peer.sin6_port = htons(179);

		if (connect(s, (sockaddr *)&peer, sizeof(peer)) == 0) {
			change_state_to(CONNECT);
			connected();
		} else if (errno == EINPROGRESS) {
			change_state_to(CONNECT);

			sock.register_fd(s, socket_base::Write);
		} else {
			close(s);
		}
	}
}

void bgp_neighbor::connected() {
	int s = sock.fd();

	ibuf.clear();
	obuf.clear();

	int err;
	socklen_t errlen = sizeof(err);
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0 && err == 0) {
		if (should_log(VERBOSE))
			log().writeline("Connected to peer.");

		sock.monitor(socket_base::Read);

		finish_connect_setup();

		trigger_open();
	} else {
		sock.unregister();

		if (should_log(VERBOSE))
			log().perror("Failed to connect to peer");

		change_state_to(IDLE);
	}
}

bool bgp_neighbor::new_connection_from(int sock) {
	if (active()) {
		if (should_log(DEBUG))
			log().writeline("Refused connection, already connected.");
		return false;
	}

	if (currstate < IDLE) {
		if (should_log(DEBUG))
			log().writeline("Refused connection, disabled by configuration.");
		return false;
	}

	activate_with(sock);

	return true;
}

void bgp_neighbor::timed_out() {
	if (currstate <= IDLE)
		return;

	if (should_log(VERBOSE))
		log().writeline("Hold-time timeout.");

	change_state_to(IDLE);

	localholdtimer.restart(true);
}

bool bgp_neighbor::handle_open(bgp_open_message &msg) {
	if (msg.version < 4) {
		if (should_log(DEBUG))
			log().xprintf("Bad message version (%i).\n",
				      (int)msg.version);

		send_notification(2, 1);

		change_state_to(IDLE);

		return false;
	}

	uint16_t as = as_number();

	if (as && as != msg.as) {
		if (should_log(VERBOSE))
			log().xprintf("AS number mismatch, expected %u got %u.\n",
				      (uint32_t)as, (uint32_t)msg.as);
		send_notification(2, 2);
		change_state_to(IDLE);
		return false;
	}

	if (currstate == ACTIVE) {
		if (!trigger_open()) {
			change_state_to(IDLE);
			return false;
		}
		send_keepalive();
	} else if (currstate != OPEN_SENT) {
		change_state_to(IDLE);
		return false;
	}

	if (!as) {
		/* sigh */
		char foo[64];
		snprintf(foo, sizeof(foo), "%u", msg.as);
		set_property("peer-as", foo);
	}

	if (should_log(NORMAL))
		log().xprintf("Neighbor is AS %u.\n", (uint32_t)msg.as);

	holdtimer.start_or_update(msg.holdtime * 1000, false, false);

	send_keepalive();
	localholdtimer.restart(false);

	change_state_to(OPEN_CONFIRM);

	return true;
}

void bgp_neighbor::handle_keepalive() {
	if (currstate == OPEN_CONFIRM)
		change_state_to(ESTABLISHED);

	if (currstate == ESTABLISHED) {
		holdtimer.restart();
	}

	lastka = tval::now();
}

const char *bgp_neighbor::_state_name(state s) {
	switch (s) {
	case INACTIVE:
		return "INACTIVE";
	case IDLE:
		return "IDLE";
	case CONNECT:
		return "CONNECT";
	case ACTIVE:
		return "ACTIVE";
	case OPEN_SENT:
		return "OPEN_SENT";
	case OPEN_CONFIRM:
		return "OPEN_CONFIRM";
	case ESTABLISHED:
		return "ESTABLISHED";
	}

	return "UNKNOWN";
}

void bgp_neighbor::change_state_to(state s) {
	if (s == currstate)
		return;

	if (should_log(EXTRADEBUG))
		log().xprintf("State change %s -> %s.\n",
			      _state_name(currstate), _state_name(s));

	if (s == ESTABLISHED) {
		prefixcount = 0;

		g_mrd->mrib().install_listener(this);
	} else {
		if (currstate == ESTABLISHED)
			g_mrd->mrib().origin_lost(this);
	}

	if (s <= IDLE) {
		if (sock.fd() > 0) {
			send_notification(Cease);

			::shutdown(sock.fd(), SHUT_RDWR);
			sock.unregister();

			holdtimer.stop();
		}

		g_mrd->clear_tasks(this);
		work_pending = false;
		work_buffer.clear();
	}

	currstate = s;
}

void bgp_neighbor::prefix_added(const inet6_addr &prefix, mrib_def::metric_def metric,
				const mrib_def::prefix &pinfo) {
	bgp_update_message msg;

	if (pinfo.flags & mrib_def::prefix::NO_EXPORT)
		return;

	/* No path to neighbor? */
	if (!peer_interface())
		return;

	if (!run_filter(output_filter, prefix))
		return;

	const bgp_prefix *bgppinfo = 0;

	if (bgp->has_neighbor((bgp_neighbor *)pinfo.owner)) {
		bgppinfo = (const bgp_prefix *)&pinfo;

		// Don't advertise IBGP originated routes to IBGP neighs
		if (mode() == IBGP && ((bgp_neighbor *)pinfo.owner)->mode() == IBGP)
			return;

		if (mode() == EBGP && (!bgppinfo->should_export || !bgppinfo->should_advertise))
			return;
	}

	if (bgppinfo) {
		msg.origin = bgppinfo->bgp_origin;
		msg.as_path = bgppinfo->as_path;
		msg.localpref = bgppinfo->localpref;
		msg.med = bgppinfo->metric;
	} else {
		msg.origin = bgp_update_message::IGP;
	}

	in6_addr nh = peer_interface()->primary_addr();
	inet6_addr linklocal = *peer_interface()->linklocal();

	if (mode() == EBGP) {
		msg.as_path.prepend(bgp->as_number());
	}

	if (!run_route_map(output_rmap, prefix, nh, msg.as_path,
			   msg.localpref, msg.med))
		return;

	if (!IN6_IS_ADDR_UNSPECIFIED(&nh))
		msg.nexthops.push_back(nh);
	if (!linklocal.is_any())
		msg.nexthops.push_back(linklocal);

	if (msg.nexthops.empty())
		return;

	msg.prefixes.push_back(prefix);

	send_update(msg);

	if (should_log(DEBUG))
		log().xprintf("Uploaded prefix %{Addr}.\n", prefix);
}

void bgp_neighbor::prefix_lost(const inet6_addr &prefix, mrib_def::metric_def metric,
				const mrib_def::prefix &pinfo) {
	/* XXX unimplemented, route withdrawal */
}

void bgp_neighbor::output_prefix_info(base_stream &ctx, const mrib_def::prefix &_info) const {
	const bgp_prefix &info = (const bgp_prefix &)_info;

	base_stream &os = ctx.write("AS_PATH:");

	for (bgp_as_path::const_iterator i =
			info.as_path.begin(); i != info.as_path.end(); ++i)
		os.xprintf(" %u", (uint32_t)*i);

	os.xprintf(", BGP Metric: %u", (uint32_t)info.metric);
	if (info.localpref != DEFAULT_LOCAL_PREF)
		os.xprintf(", LocalPref: %u", (uint32_t)info.localpref);

	os.newl();
}

bool bgp_neighbor::set_property(const char *key, const char *value) {
	if (!strcmp(key, "peer-as")) {
		// can't change AS while connected
		if (currstate > IDLE)
			return false;

		uint16_t asnumber;
		if (!_parse_asnumber(value, asnumber))
			return false;

		AS->set_readonly();
	} else if (!strcmp(key, "mode")) {
		if (!strcasecmp(value, "eBGP") && !strcasecmp(value, "iBGP"))
			return false;
	}

	return node::set_property(key, value);
}

bool bgp_neighbor::call_method(int id, base_stream &out,
			       const std::vector<std::string> &args) {
	switch (id) {
	case bgp_neigh_method_filter:
	case bgp_neigh_method_route_map:
		return conf_filter_rmap(id == bgp_neigh_method_filter, args);
	case bgp_neigh_method_activate:
		{
			if (!args.empty())
				return false;
			if (currstate < IDLE)
				change_state_to(IDLE);
			return true;
		}
	case bgp_neigh_method_reconnect:
		return reconnect();
	case bgp_neigh_method_debug:
		return output_info(out, true);
	case bgp_neigh_method_alias:
		{
			if (args.size() != 1)
				return false;

			const char *value = args[0].c_str();

			inet6_addr addr;
			/* addresses cant be aliases */
			if (addr.set(value))
				return false;

			bgp_neighbor *n = bgp->neighs().get_alias(value);
			if (n)
				return n == this;

			if (!alias.empty()) {
				if (strcmp(alias.c_str(), value)) {
					bgp->neighs().remove_alias(alias.c_str());
				}
			}

			alias = value;

			bgp->neighs().add_alias(value, this);

			return true;
		}
	}

	return node::call_method(id, out, args);
}

bool bgp_neighbor::negate_method(int id, base_stream &out,
				 const std::vector<std::string> &args) {
	switch (id) {
	case bgp_neigh_method_activate:
		{
			if (!args.empty())
				return false;
			if (currstate >= IDLE)
				change_state_to(INACTIVE);
			return true;
		}
	}

	return node::negate_method(id, out, args);
}

static inline int _next_seq(const std::map<int, std::string> &l) {
	if (l.empty())
		return 100;
	else
		return l.rbegin()->first + 100;
}

bool bgp_neighbor::conf_filter_rmap(bool filter,
				    const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	int seq = -1;
	bool in = false;

	int k = 1;

	if (args[0] != "in" && args[0] != "out") {
		if (args.size() != 3)
			return false;
		if (!_parse_int(args[0].c_str(), seq))
			return false;
		if (args[1] == "in")
			in = true;
		else if (args[1] == "out")
			in = false;
		else
			return false;
		k = 2;
	} else {
		if (args.size() != 2)
			return false;
		in = (args[0] == "in");
	}

	std::map<int, std::string> *target = 0;

	if (filter)
		target = in ? &input_filter : &output_filter;
	else
		target = in ? &input_rmap : &output_rmap;

	if (seq < 0)
		seq = _next_seq(*target);

	(*target)[seq] = args[k];

	return true;
}

bool bgp_neighbor::output_info(base_stream &ctx, const std::vector<std::string> &) const {
	return output_info(ctx, false);
}

static void _dump_fltrmap(base_stream &ctx, const char *type,
			  const std::map<int, std::string> &flt) {
	for (std::map<int, std::string>::const_iterator i =
			flt.begin(); i != flt.end(); ++i) {
		ctx.xprintf("%i %s %s\n", i->first, type, i->second.c_str());
	}
}

bool bgp_neighbor::output_info(base_stream &ctx, bool debug) const {
	ctx.writeline(peeraddr_s.c_str());

	ctx.inc_level();
	if (currstate == ESTABLISHED) {
		ctx.xprintf("AS: %u\n", (uint32_t)as_number());
		ctx.xprintf("Status: Connected for %{duration} [KAs: "
			    "%{duration} / %{duration}]\n",
			    time_duration(tval::now() - lastconnect),
			    time_duration(tval::now() - lastka),
			    time_duration(tval::now() - lastsentka));
		if (debug) {
			ctx.xprintf("InB: %ub OutB: %ub\n",
				    (uint32_t)ibuf.data_length(),
				    (uint32_t)obuf.data_length());
			ctx.xprintf("WorkBuffer: %u (Max: %u)\n",
				    (uint32_t)work_buffer.size(),
				    (uint32_t)max_work_buffer_size);
		} else
			ctx.xprintf("Prefix Count: %u\n", (uint32_t)prefixcount);
	} else {
		ctx.xprintf("Status: Disconnected (current state %s)",
			    _state_name(currstate));
		if (currstate > INACTIVE) {
			ctx.xprintf(", reconnecting in %{duration}",
				    localholdtimer.time_left_d());
		}
		ctx.newl();
	}

	interface *intf = peer_interface();

	ctx.xprintf("Peer interface: %s\n", intf ? intf->name() : "None");

	if (!input_filter.empty() || !output_filter.empty()) {
		ctx.writeline("Filters:");
		ctx.inc_level();

		_dump_fltrmap(ctx, "in", input_filter);
		_dump_fltrmap(ctx, "out", output_filter);

		ctx.dec_level();
	}

	if (!input_rmap.empty() || !output_rmap.empty()) {
		ctx.writeline("Route-maps:");
		ctx.inc_level();

		_dump_fltrmap(ctx, "in", input_rmap);
		_dump_fltrmap(ctx, "out", output_rmap);

		ctx.dec_level();
	}

	ctx.dec_level();

	return true;
}

void bgp_neighbor::trigger_send_peer() {
	if (!obuf.empty())
		sock.monitor(socket_base::Read | socket_base::Write);
}

base_stream &bgp_neighbor::log() const {
	return node::log().xprintf("%s ", peeraddr_s.c_str());
}

void bgp_neighbor::data_available(uint32_t type) {
	if (currstate == CONNECT) {
		connected();
		return;
	}

	if (type == socket_base::Write) {
		if (!obuf.empty()) {
			int consumed = send(sock.fd(), obuf.head(),
					    obuf.data_length(), MSG_DONTWAIT);

			if (consumed > 0) {
				obuf.advance_head(consumed);
				obuf.compact();
			}
		}

		if (obuf.empty())
			sock.monitor(socket_base::Read);

		return;
	}

	int len;

	if ((len = recv(sock.fd(), ibuf.tail(),
			ibuf.available_length(), MSG_DONTWAIT)) <= 0) {
		if (errno != EAGAIN && errno != EINTR && errno != EINPROGRESS) {
			if (should_log(MESSAGE_ERR))
				log().perror("Error while receiving");

			change_state_to(IDLE);
		}
		return;
	}

	ibuf.advance_tail(len);

	while (1) {
		bgp_message msg;

		if (!msg.decode(ibuf))
			break;

		m_stats.counter(AllCount, RX)++;

		if (should_log(MESSAGE_CONTENT))
			log().xprintf("Received %s Message, length = %u\n",
				      msg.type_name(), (uint32_t)msg.len);

		if (msg.type == BGP_KEEPALIVE) {
			m_stats.counter(KeepaliveCount, RX)++;

			handle_keepalive();
		} else if (msg.type == BGP_OPEN) {
			m_stats.counter(OpenCount, RX)++;

			bgp_open_message open(msg);
			if (open.decode(ibuf)) {
				if (!handle_open(open)) {
					return;
				}
			} else {
				m_stats.counter(OpenCount, Bad)++;
			}
		} else if (msg.type == BGP_UPDATE) {
			m_stats.counter(UpdateCount, RX)++;

			bgp_update_message update(msg);
			if (update.decode(ibuf))
				build_update_work(update);
			else
				m_stats.counter(UpdateCount, Bad)++;
		} else if (msg.type == BGP_NOTIFICATION) {
			m_stats.counter(NotificationCount, RX)++;

			bgp_notification_message notify;
			if (notify.decode(ibuf)) {
				if (!handle_notify(notify))
					return;
			} else {
				m_stats.counter(NotificationCount, Bad)++;
			}
		} else {
			m_stats.counter(AllCount, Bad)++;

			if (should_log(MESSAGE_ERR))
				log().writeline("Received bad message, dropping.");
		}
	}

	ibuf.compact();

	if (!work_pending && !work_buffer.empty()) {
		if (should_log(INTERNAL_FLOW))
			log().writeline("Registering WorkPending");

		work_pending = true;
		g_mrd->register_task(this, WorkPending);
	}
}

static inline bool has_community(const bgp_communities &coms, const bgp_community &c) {
	return std::find(coms.begin(), coms.end(), c) != coms.end();
}

void bgp_neighbor::event(int event, void *ptr) {
	if (event == mrd::StartupEvent) {
		set_destination(peeraddr);
		return;
	}

	if (event != WorkPending) {
		node::event(event, ptr);
		return;
	}

	if (!work_buffer.empty()) {
		tms _tmp;
		clock_t start = times(&_tmp);

		const work_token &t = work_buffer.front();

		if (should_log(MESSAGE_CONTENT))
			log().xprintf("Working on prefix %{Addr}\n", t.prefix);

		if (t.action == InstallPrefix) {
			if (run_filter(input_filter, t.prefix))
				install_prefix(t.prefix, t.origin, t.nexthop, t.as_path, t.communities);

		} else if (t.action == RemovePrefix) {
			mrib_def::prefix *pinfo = g_mrd->mrib().get_prefix(t.prefix, this);

			if (pinfo) {
				g_mrd->mrib().remove_prefix(pinfo);
			}
		}

		work_buffer.pop_front();

		clock_t end = times(&_tmp);

		/* add this to 'if debug' block */

		uint32_t spent = (uint32_t)(((end - start) * 1000) / sysconf(_SC_CLK_TCK));

		if (should_log(INTERNAL_FLOW))
			log().xprintf("Spent %u milisecs.\n", spent);
	}

	/* possibly still work todo */
	if (!work_buffer.empty()) {
		g_mrd->register_task(this, WorkPending);
	} else {
		work_pending = false;

		if (should_log(INTERNAL_FLOW))
			log().writeline("Finished all pending Work.");
	}
}

void bgp_neighbor::install_prefix(const inet6_addr &prefix, uint8_t origin,
				  const in6_addr &nh, const bgp_as_path &as_path,
				  const bgp_communities &communities) {
	bgp_prefix *pinfo = (bgp_prefix *)g_mrd->mrib().get_prefix(prefix, this);

	if (pinfo) {
		if (pinfo->as_path != as_path) {
			pinfo = 0;
		}
	}

	bool update = pinfo != 0;

	if (!pinfo) {
		pinfo = bgp->prefix_pool.request_obj(this, as_path);
		if (pinfo)
			pinfo->nexthop = nh;
	} else {
		if (should_log(INTERNAL_FLOW))
			log().xprintf("Updating %{Addr}, had previous record.\n",
				      prefix);
	}

	if (pinfo) {
		/* XXX if update, match BGP rules, local-pref, as-path, metric */

		bool accepted = run_route_map(input_rmap, prefix,
					      pinfo->nexthop, pinfo->as_path,
					      pinfo->metric, pinfo->localpref);

		if (accepted) {
			pinfo->bgp_origin = origin;

			if (has_community(communities, no_export))
				pinfo->should_export = false;
			if (has_community(communities, no_advertise))
				pinfo->should_advertise = false;

			pinfo->intf = peer_interface();

			/* this is bogus, we must have a BGP mrib and only
			 * install prefixes into the main mrib that are better
			 * in terms of local-pref, as_path, etc */
			pinfo->metric = pinfo->as_path.size() * 10
					  + (6000 - (20 * pinfo->localpref));

			if (update) {
				g_mrd->mrib().update_prefix(pinfo);
			} else {
				if (g_mrd->mrib().install_prefix(prefix, pinfo)) {
					prefixcount++;
				} else {
					if (should_log(DEBUG))
						log().xprintf("Failed to install prefix %{Addr}.\n",
							      prefix);
				}
			}
		} else {
			if (update)
				g_mrd->mrib().remove_prefix(pinfo);
			else
				delete pinfo;

			if (should_log(EXTRADEBUG))
				log().xprintf("Filter rejected prefix %{Addr}.\n",
					      prefix);
		}
	} else {
		if (should_log(DEBUG))
			log().xprintf("Failed to install prefix %{Addr}, "
				      "not enough memory.\n", prefix);
	}
}

bool bgp_neighbor::run_filter(const std::map<int, std::string> &args,
			      const inet6_addr &prefix) const {
	for (std::map<int, std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		bgp_acl *acl = bgp->get_acl(i->second.c_str());

		if (!acl || !acl->accepts(prefix))
			return false;
	}

	return true;
}

bool bgp_neighbor::run_route_map(const std::map<int, std::string> &args,
				 const inet6_addr &prefix, in6_addr &nh,
				 bgp_as_path &aspath, mrib_def::metric_def &m,
				 uint32_t &localpref) const {
	for (std::map<int, std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		bgp_rmap *rmap = bgp->get_rmap(i->second.c_str());

		if (!rmap || !rmap->applies(prefix, nh, aspath, m, localpref))
			return false;
	}

	return true;
}

void bgp_neighbor::build_update_work(bgp_update_message &msg) {
	if (should_log(INTERNAL_FLOW))
		log().xprintf("Handle update with %u prefixes and %u "
			      "nexthops.\n", (uint32_t)msg.prefixes.size(),
			      (uint32_t)msg.nexthops.size());

	if (msg.nexthops.empty())
		return;

	work_token t;

	t.origin = msg.origin;
	t.as_path = msg.as_path;
	t.communities = msg.communities;

	for (std::vector<inet6_addr>::const_iterator i = msg.prefixes.begin();
			i != msg.prefixes.end(); ++i) {

		t.action = InstallPrefix;
		t.prefix = *i;
		t.nexthop = *msg.nexthops.begin();

		work_buffer.push_back(t);
	}

	for (std::vector<inet6_addr>::const_iterator i = msg.unreach_prefixes.begin();
			i != msg.unreach_prefixes.end(); i++) {

		t.action = RemovePrefix;
		t.prefix = *i;
		t.nexthop = in6addr_any;

		work_buffer.push_back(t);
	}

	if (work_buffer.size() > max_work_buffer_size)
		max_work_buffer_size = work_buffer.size();
}

bool bgp_neighbor::handle_notify(bgp_notification_message &msg) {
	const char *err = "Unknown", *suberr = "Unknown";

	if (valid_error(msg.errorcode, msg.suberrorcode)) {
		err = error_messages[msg.errorcode-1];
		if (msg.errorcode >= 1 && msg.errorcode <= 3)
			suberr = suberror_messages[msg.errorcode-1][msg.suberrorcode-1];
	}

	if (should_log(NORMAL))
		log().xprintf("Neighbour terminated connection, reason: %s (%s)\n",
			      err, suberr);

	change_state_to(IDLE);

	return false;
}

static const bgp_open_message::capability ipv6_multicast(bgp_open_message::IPV6,
							bgp_open_message::MULTICAST);

bool bgp_neighbor::encode_msg(const bgp_message &msg) {
	if (!msg.encode(obuf)) {
		if (should_log(EXTRADEBUG))
			log().xprintf("Failed to encode %s message.\n",
				      msg.type_name());
		return false;
	}

	return true;
}

bool bgp_neighbor::trigger_open() {
	bgp_open_message msg;

	msg.as = bgp->as_number();
	msg.holdtime = holdtime();
	msg.bgpid = bgp->id();

	msg.capabilities.push_back(ipv6_multicast);

	if (!send_open(msg))
		return false;

	change_state_to(OPEN_SENT);

	return true;
}

void bgp_neighbor::send_keepalive() {
	bgp_message ka(4);

	if (!ka.encode(obuf)) {
		if (should_log(DEBUG))
			log().writeline("Failed to send Keep-Alive, no buffer space.");

		change_state_to(IDLE);
	} else {
		m_stats.counter(KeepaliveCount, TX)++;

		trigger_send_peer();
		lastsentka = tval::now();

		if (should_log(MESSAGE_SIG))
			log().writeline("Sent Keep-Alive");
	}
}

void bgp_neighbor::send_notification(uint8_t code, uint8_t subcode) {
	bgp_notification_message msg;
	msg.errorcode = code;
	msg.suberrorcode = subcode;

	if (encode_msg(msg)) {
		m_stats.counter(NotificationCount, TX)++;

		trigger_send_peer();
	}
}

void bgp_neighbor::handle_localholdtime() {
	if (should_log(INTERNAL_FLOW))
		log().xprintf("Handle holdtime timer in %s\n",
			      _state_name(currstate));

	if (currstate == ESTABLISHED)
		send_keepalive();
	else if (currstate == IDLE)
		start_connect();
	else if (currstate > IDLE)
		change_state_to(IDLE);
}

bool bgp_neighbor::send_message(const bgp_message &msg) {
	if (!encode_msg(msg))
		return false;

	trigger_send_peer();

	return true;
}

bool bgp_neighbor::send_update(const bgp_update_message &msg) {
	if (send_message(msg)) {
		m_stats.counter(UpdateCount, TX)++;
		return true;
	}

	return false;
}

bool bgp_neighbor::send_open(const bgp_open_message &msg) {
	if (send_message(msg)) {
		m_stats.counter(OpenCount, TX)++;
		return true;
	}

	return false;
}

bool bgp_neighbor::reconnect() {
	if (currstate > INACTIVE) {
		change_state_to(IDLE);

		localholdtimer.start_or_update(1000, true);
	}

	return true;
}

bgp_acl::bgp_acl(bgp_access_lists *parent, const char *name)
	: node(parent, name) {
}

bool bgp_acl::check_startup() {
	if (!node::check_startup())
		return false;

	import_methods(bgp_acl_methods);

	return true;
}

bool bgp_acl::call_method(int id, base_stream &out,
			  const std::vector<std::string> &args) {
	switch (id) {
	case bgp_acl_method_prefix:
		return prefix(args);
	}

	return node::call_method(id, out, args);
}

bool bgp_acl::negate_method(int id, base_stream &out,
			    const std::vector<std::string> &args) {
	switch (id) {
	case bgp_acl_method_prefix:
		return no_prefix(args);
	}

	return node::negate_method(id, out, args);
}

bool bgp_acl::prefix(const std::vector<std::string> &args) {
	entry e;
	bool has_pf = false;
	int seq = -1;

	e.mode = false;
	e.ge = e.le = -1;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		if (*i == "permit" || *i == "deny") {
			if (has_pf)
				return false;
			e.mode = (*i == "permit");
			++i;
			if (i == args.end())
				return false;
			if (!e.prefix.set(i->c_str()))
				return false;
			has_pf = true;
		} else if (*i == "seq") {
			++i;
			if (seq != -1 || i == args.end())
				return false;
			char *end;
			uint32_t val = strtoul(i->c_str(), &end, 10);
			if (*end || val > INT_MAX)
				return false;
			seq = val;
		} else if (*i == "ge" || *i == "le") {
			bool l = (*i == "le");
			++i;
			if (i == args.end())
				return false;
			if ((l && (e.le != -1)) || (!l && (e.ge != -1)))
				return false;
			char *end;
			uint32_t val = strtoul(i->c_str(), &end, 10);
			if (*end || val > 128)
				return false;
			if (l)
				e.le = val;
			else
				e.ge = val;
		} else {
			return false;
		}
	}

	if (e.ge != -1 && e.le != -1) {
		if (e.ge > e.le)
			return false;
	}

	if (seq == -1) {
		if (m_entries.empty())
			seq = 100;
		else
			seq = (m_entries.rbegin()->first / 100) * 100 + 200;
	}

	m_entries[seq] = e;

	return true;
}

bool bgp_acl::no_prefix(const std::vector<std::string> &args) {
	return false;
}

bool bgp_acl::output_info(base_stream &out,
			  const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	for (entries::const_iterator i =
		m_entries.begin(); i != m_entries.end(); ++i) {
		out.xprintf("prefix seq %i %s %{Addr}", i->first,
			    i->second.mode ? "permit" : "deny",
			    i->second.prefix);
		if (i->second.ge != -1)
			out.xprintf(" ge %i", (int)i->second.ge);
		if (i->second.le != -1)
			out.xprintf(" le %i", (int)i->second.le);
		out.writeline(";");
	}

	return true;
}

bool bgp_acl::accepts(const inet6_addr &prefix) const {
	for (entries::const_iterator i =
		m_entries.begin(); i != m_entries.end(); ++i) {
		if (i->second.prefix.matches(prefix)) {
			if (i->second.ge != -1)
				if (i->second.ge > (int)prefix.prefixlen)
					continue;
			if (i->second.le != -1)
				if (i->second.le < (int)prefix.prefixlen)
					continue;
			return i->second.mode;
		}
	}

	return false;
}

bgp_access_lists::bgp_access_lists(node *parent)
	: node(parent, "access-list") {
}

node *bgp_access_lists::create_child(const char *name) {
	node *n = new bgp_acl(this, name);
	if (!n || !n->check_startup()) {
		delete n;
		return 0;
	}

	add_child(n);

	return n;
}

bool bgp_access_lists::output_info(base_stream &out,
				   const std::vector<std::string> &args) const {
	for (properties::const_iterator i =
			m_properties.begin(); i != m_properties.end(); ++i) {
		if (i->second.is_child()) {
			bgp_acl *n = (bgp_acl *)i->second.get_node();

			out.xprintf("access-list %s {\n", n->name());
			out.inc_level();
			n->output_info(out, args);
			out.dec_level();
			out.writeline("}");
		}
	}

	return true;
}

bgp_rmap::bgp_rmap(bgp_route_maps *parent, const char *name)
	: node(parent, name) {
}

bool bgp_rmap::check_startup() {
	if (!node::check_startup())
		return false;

	import_methods(bgp_rmap_methods);

	return true;
}

bool bgp_rmap::call_method(int id, base_stream &out,
			   const std::vector<std::string> &args) {
	if (id == bgp_rmap_method_match) {
		if (args.size() != 1)
			return false;
		m_match_filter = args[0];
		return true;
	} else if (id == bgp_rmap_method_prepend_aspath) {
		if (args.size() != 1)
			return false;

		action a;
		a.type = PREPEND_ASPATH;

		if (!_parse_asnumber(args[0].c_str(), a.v.as))
			return false;

		m_actions.push_back(a);

		return true;
	} else if (id == bgp_rmap_method_set) {
		if (args.size() != 2)
			return false;
		action a;
		if (args[0] == "local-pref" || args[0] == "metric") {
			a.type = (args[0] == "local-pref") ? LOCAL_PREF : METRIC;
			if (!_parse_int(args[1], a.v.metric))
				return false;
			if (a.v.metric < 0)
				return false;
			/* XXX */
			if (a.type == LOCAL_PREF && a.v.metric > 300)
				return false;
		} else if (args[0] == "community") {
			a.type = COMMUNITY;

			bgp_community c;
			if (!_parse_community(args[1], c))
				return false;
			a.v.c.first = c.first;
			a.v.c.second = c.second;
		} else
			return false;

		m_actions.push_back(a);

		return true;
	}

	return node::call_method(id, out, args);
}

bool bgp_rmap::negate_method(int id, base_stream &out,
			   const std::vector<std::string> &args) {
	if (id == bgp_rmap_method_match) {
		m_match_filter = std::string();

		return true;
	} else if (id == bgp_rmap_method_prepend_aspath) {
	} else if (id == bgp_rmap_method_set) {
	}

	return node::negate_method(id, out, args);
}

bool bgp_rmap::output_info(base_stream &out,
			   const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	if (!m_match_filter.empty())
		out.xprintf("match %s;\n", m_match_filter.c_str());

	for (actions::const_iterator i =
		m_actions.begin(); i != m_actions.end(); ++i) {
		switch (i->type) {
		case PREPEND_ASPATH:
			out.xprintf("prepend-aspath %u;\n", (uint32_t)i->v.as);
			break;
		case LOCAL_PREF:
			out.xprintf("set local-pref %u;\n", (uint32_t)i->v.metric);
			break;
		case METRIC:
			out.xprintf("set metric %u;\n", (uint32_t)i->v.metric);
			break;
		case COMMUNITY:
			out.xprintf("set community %u:%u;\n",
				    (uint32_t)i->v.c.first,
				    (uint32_t)i->v.c.second);
			break;
		}
	}

	return true;
}

bool bgp_rmap::applies(const inet6_addr &prefix, in6_addr &nh,
		       bgp_as_path &aspath, mrib_def::metric_def &m,
		       uint32_t &localpref) const {
	if (!m_match_filter.empty()) {
		bgp_acl *acl = bgp->get_acl(m_match_filter.c_str());

		if (!acl || !acl->accepts(prefix))
			return false;
	}

	for (actions::const_iterator i =
		m_actions.begin(); i != m_actions.end(); ++i) {
		if (i->type == PREPEND_ASPATH) {
			/* i->v.as */
		} else if (i->type == LOCAL_PREF) {
			localpref = i->v.metric;
		} else if (i->type == METRIC) {
			m = i->v.metric;
		} else if (i->type == COMMUNITY) {
			/* i->v.c */
		}
	}

	return true;
}

bgp_route_maps::bgp_route_maps(node *parent)
	: node(parent, "route-map") {
}

node *bgp_route_maps::create_child(const char *name) {
	node *n = new bgp_rmap(this, name);
	if (!n || !n->check_startup()) {
		delete n;
		return 0;
	}

	add_child(n);

	return n;
}

bool bgp_route_maps::output_info(base_stream &out,
				 const std::vector<std::string> &args) const {
	for (properties::const_iterator i =
			m_properties.begin(); i != m_properties.end(); ++i) {
		if (i->second.is_child()) {
			bgp_rmap *n = (bgp_rmap *)i->second.get_node();

			out.xprintf("route-map %s {\n", n->name());
			out.inc_level();
			n->output_info(out, args);
			out.dec_level();
			out.writeline("}");
		}
	}

	return true;
}

base_stream &bgp_module::log() const {
	return node::log().write("BGP, ");
}


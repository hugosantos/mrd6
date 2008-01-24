/*
 * Multicast Routing Daemon (MRD)
 *   mrd.h
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

#ifndef _mrd_mrd_h_
#define _mrd_mrd_h_

#include <mrd/interface.h>
#include <mrd/source_discovery.h>
#include <mrd/mrib.h>
#include <mrd/node.h>
#include <mrd/timers.h>

#include <mrd/packet_buffer.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/ucontext.h> /* POSIX ucontext_t */

#include <deque>
#include <list>
#include <map>
#include <queue>
#include <set>

#include <regex.h>

class group;
class router;
class rib_def;
class mfa_core;
class confnode;
class intfconf;
class icmp_base;
class groupconf;
class interface;
class event_sink;
class mrd_module;
class base_stream;
class mfa_instance;
class intfconf_node;
class groupconf_node;
class group_interface;
class source_discovery_sink;
class source_discovery_origin;

/*!
 * callback based socket wrapper implementation.
 */
class socket_base {
public:
	socket_base(const char *);
	virtual ~socket_base();

	const char *name() const;

	enum {
		Read = 1,
		Write = 2
	};

	virtual void callback(uint32_t) = 0;

	bool register_fd(int fd, uint32_t flags = Read);
	void unregister(bool close = true);

	bool monitor(uint32_t flags = Read);

	int fd() const { return _fd; }
	uint64_t hits() const { return _hits; }

	/* these are required in _handle_pending_socks */
	std::string _name;
	int _fd;
	uint64_t _hits;
};

/*!
 * callback based ipv6 socket wrapper implementation.
 */
class socket6_base : public socket_base {
public:
	socket6_base(const char *);

	bool register_fd(int fd, uint32_t flags = Read);

	int sendto(const void *, uint16_t, const sockaddr_in6 *);
	int sendto(const void *, uint16_t, const sockaddr_in6 *,
		   const sockaddr_in6 *from, int = 0);
	int recvfrom(void *, uint16_t, sockaddr_in6 *);
	int recvfrom(void *, uint16_t);

	/*!
	 * Joins the supplied multicast group in the supplied interface
	 */
	bool join_mc(interface *, const in6_addr &);
	/*!
	 * Leaves the supplied multicast group in the supplied interface
	 */
	bool leave_mc(interface *, const in6_addr &);

	bool enable_mc_loop(bool);

	bool set_hoplimit(int);
	bool set_mcast_hoplimit(int);

	/*!
	 * Retrieves the last received packet's source address
	 */
	const sockaddr_in6 &source_address() const { return _recvfrom; }

	/*!
	 * Retrives the last received packet's destination
	 * address and receiving interface
	 */
	bool destination_address(sockaddr_in6 &, int &);

	/*! Returns the next cmsghdr, as the first one is always IPV6_PKTINFO */
	cmsghdr *next_cmsghdr(int maxlen) const;

private:
	/* in6_pktinfo is 20 bytes length */
	/* cmsghdr is 16 bytes length */
	/* msghdr is 28 bytes length */

	/* reserve a cmsg(20 bytes) for other uses */
	/* uint8_t _ctlbuf[CMSG_SPACE(sizeof(in6_pktinfo)) + CMSG_SPACE(20)]; */
	uint8_t _ctlbuf[96];
	msghdr _h;
	sockaddr_in6 _recvfrom;
};

inline const char *socket_base::name() const {
	return _name.c_str();
}

/*!
 * template based socket wrapper implementation.
 */
template<typename Holder>
class socket0 : public socket_base {
public:
	typedef std::mem_fun1_t<void, Holder, uint32_t> callback_def;

	socket0(const char *, Holder *h, callback_def c);

	void callback(uint32_t);

private:
	Holder *_h;
	callback_def _cb;
};

template<typename H> inline socket0<H>::socket0(const char *name, H *h, callback_def c)
	: socket_base(name), _h(h), _cb(c) {}

template<typename H> inline void socket0<H>::callback(uint32_t flags) {
	_cb(_h, flags);
}

/*!
 * template based ipv6 socket wrapper implementation.
 */
template<typename Holder>
class socket6 : public socket6_base {
public:
	typedef std::mem_fun1_t<void, Holder, uint32_t> callback_def;

	socket6(const char *, Holder *h, callback_def c);

	void callback(uint32_t);

private:
	Holder *_h;
	callback_def _cb;
};

template<typename H> inline socket6<H>::socket6(const char *name, H *h, callback_def c)
	: socket6_base(name), _h(h), _cb(c) {}

template<typename H> inline void socket6<H>::callback(uint32_t flags) {
	_cb(_h, flags);
}

class group_request_interface {
public:
	virtual ~group_request_interface() {}

	virtual bool request_group(interface *, const inet6_addr &,
			const inet6_addr &, router *) const = 0;
};

/*!
 * base core class. Provides interface, group, router, etc management.
 */
class mrd : public node {
public:
	mrd();
	virtual ~mrd();

	bool check_startup(const char *, bool autoload = true);
	void start();
	void shutdownx();

	bool show_mrd_version(base_stream &) const;
	void show_base_info(base_stream &) const;

	/*! Is the router already inside the processing loop. */
	bool is_running() const { return m_state == Running; }

	/*! Returns true if the router has the supplied address */
	bool has_address(const in6_addr &) const;
	/*!
	 * Returns true if the supplied address is in one of the
	 * router's subnets
	 */
	bool in_same_subnet(const in6_addr &) const;

	/*! Returns a reference to the MRIB */
	mrib_def &mrib() { return m_mrib; }

	/*! Returns a reference to the RIB */
	rib_def &rib() const { return *m_rib_handler; }

	/*! Returns a reference to the ICMP handling instance */
	icmp_base &icmp() const { return *m_icmp; }

	/*! Registers a new routing protocol */
	bool register_router(router *);
	/*! Unregisters a routing protocol */
	void unregister_router(router *);

	/*!
	 * Registers a RIB handler. This is only possible during the
	 * initial configuration parsing. Returns false if we already
	 * have an handler.
	 */
	bool register_rib(rib_def *);

	/*!
	 * Nodes may register themselves to be notified of the startup
	 * event. That is, that they may use all MRD6's components.
	 */
	void register_startup(node *);

	/*! Returns a previously registered router instance */
	router *get_router(const char *) const;

	mfa_core *mfa() const { return m_mfa; }

	/*! Returns an interface instance referenced by index */
	interface *get_interface_by_index(int dev) const;

	/*! Returns an interface instance referenced by name */
	interface *get_interface_by_name(const char *) const;

	interface *get_loopback_interface() const;

	typedef std::map<int, interface *> interface_list;
	/*! returns a list with all the registered interfaces */
	const interface_list &intflist() const { return m_intflist; }

	/*! Should be called by OS modules whenever a new interface is found. */
	interface *found_interface(int index, const char *name, int type,
				   int mtu, int flags);

	void check_enabled_interfaces(intfconf *);
	void broadcast_interface_state_changed(interface *);

	/*! Should be called by OS modules whenever an interface is lost */
	void lost_interface(int);

	void remove_interface(interface *);

	/*! Loads the specified module from the configured module path */
	bool load_modulex(const char *);
	bool remove_module(const char *);
	bool remove_module(mrd_module *);

	/*! Returns a reference to the root configuration node */
	node *rootconf() { return this; }

	intfconf *get_interface_configuration(const char *);
	intfconf *default_interface_configuration();

	/*! if origin=0, unregisters the supplied source discovery method
	 * named 'name'. */
	bool register_source_discovery(const char *name,
				       source_discovery_origin *origin);
	source_discovery_origin *get_source_discovery(const char *) const;

	void discovered_source(int ifindex, const inet6_addr &,
			       const inet6_addr &, source_discovery_origin *);
	void lost_source(const inet6_addr &, const inet6_addr &,
			 source_discovery_origin *);

	bool register_source_sink(source_discovery_sink *, bool);
	bool register_generic_source_sink(source_discovery_sink *, bool);

	bool set_property(const char *, const char *);
	bool increment_property(const char *, const char *);
	bool call_method(int, base_stream &, const std::vector<std::string> &);

	std::list<inet6_addr> configured_group_set(const char *rt = 0) const;
	groupconf *match_group_configuration(const inet6_addr &) const;
	groupconf *get_group_configuration(const inet6_addr &) const;
	groupconf *get_similiar_groupconf_node(const groupconf *) const;

	//
	// Group Management stuff
	//

	struct create_group_context {
		int iif;
		inet6_addr groupaddr;
		inet6_addr requester;
		std::string origin_name;
		group *result;
	};

	bool create_group(router *, node *caller, create_group_context *);
	void release_group(group *);

	/*! if prio is <= 0, the supplied instance is removed from the list */
	void register_group_creation_auth(group_request_interface *, int prio = 10);

	/*! Returns an existing group reference by address */
	group *get_group_by_addr(const inet6_addr &) const;

	typedef std::map<inet6_addr, group *> group_list;

	const group_list &group_table() const { return m_grplist; }

	/*!
	 * Registers a socket into the main event loop. Ready status events
	 * are delivered to the socket_base handle
	 */
	bool register_sock(socket_base *, int sock, uint32_t);
	/*! Unregisters a socket from the main event loop. */
	bool unregister_sock(socket_base *);
	bool monitor_sock(socket_base *, uint32_t);

	/* MRD events */
	enum {
		CreatedGroup = 'C',
		RemoveGroup = 'R',
		StartupEvent = 'S',

		NewGroup = 'G',
		ReleasedGroup = 'g',
		InterfaceStateChanged = 'I',

		ActiveStateNotification = 'A',
	};

	struct task {
		enum {
			LowPrio = 0,
			HighPrio = 10,
		};

		event_sink *target;
		int event, prio;
		void *argument;
	};

	static task make_task(event_sink *target, int event, void *opt = 0,
					int prio = task::LowPrio);

	/*!
	 * Registers a task to be executed by the main loop. The task
	 * event is then delivered to the target node.
	 */
	void register_task(const task &);
	/*!
	 * Registers a task to be executed by the main loop. The task
	 * event is then delivered to the target node.
	 */
	void register_task(event_sink *target, int event, void *opt = 0,
				int prio = task::LowPrio);
	/*! Removes any pendings tasks which target is the supplied one (slow operation) */
	void clear_tasks(event_sink *target);

	struct active_state_report {
		group *group_instance;
		in6_addr source_address;
		bool active;
	};

	void interested_in_active_states(event_sink *, bool);
	bool interest_in_active_states() const;
	void state_is_active(group *, const in6_addr &, bool);

	void load_early_module(const char *);

	timermgr *timemgr() { return &m_timermgr; }

	packet_buffer *ipktb;
	packet_buffer *opktb;

	void output_backtrace(base_stream &) const;
	char *obtain_frame_description(void *) const;

	struct posix_uctx {
		posix_uctx(ucontext_t *);

		/* this depends on the operating system _and_ platform */
		void *get_current_frame() const;

		ucontext_t *base;
	};

	bool should_log(int level) const;
	base_stream &log() const;
	base_stream &fatal() const;

	static uint32_t get_randu32();

protected:

	virtual group *allocate_group(const inet6_addr &, groupconf *) const;

private:
	bool prepare_os_components();
	void prepare_second_components();
	void add_static_modules();

	const char *loopback_interface_name() const;

	void processloop();
	void change_user();

	bool check_module_path(const char *, std::string &);
	bool add_module(const char *, mrd_module *);

	static void handle_signal(int);

	group *create_group(const inet6_addr &);
	group *create_group(const inet6_addr &, groupconf *);

	typedef std::map<std::string, router *> routers;

	enum mrd_state {
		Initial,
		PreConfiguration,
		Configuration,
		PostConfiguration,
		Running,
		ShuttingDown,
	} m_state;

	void change_state(mrd_state);

	timermgr m_timermgr;
	time_t m_startup;

	typedef std::deque<std::string> module_path;
	module_path m_module_path;

	typedef std::map<std::string, source_discovery_origin *> source_disc;
	source_disc m_source_disc;

	typedef std::vector<source_discovery_sink *> source_sinks;
	source_sinks m_source_sinks, m_all_source_sinks;

	typedef std::vector<node *> node_vector;
	node_vector m_startup_nodes;

	static_source_discovery m_static_source_disc;

	mutable log_base g_rlog;
	mrib_def m_mrib;

	routers m_routers;

	interface_list m_intflist;
	node m_intflist_node;

	group_list m_grplist;
	node m_grplist_node;

	void invalidate_intf_cache();

#define _INTERFACE_CACHE_LEN	32
	mutable interface *m_intf_cache[_INTERFACE_CACHE_LEN];

	typedef std::list<std::pair<int, group_request_interface *> > create_group_acl;
	create_group_acl m_create_group_acl;

	class intfconf_list : public node {
	public:
		intfconf_list(node *);
		~intfconf_list();

		bool check_startup();

		bool call_method(int, base_stream &,
				 const std::vector<std::string> &);
		bool negate_method(int, base_stream &,
				   const std::vector<std::string> &);

		bool is_interface_disabled(const char *) const;

		node *create_child(const char *);
		void remove_child_node(node *);

	private:
		struct disable_token {
			std::string origstr;
			regex_t r;
		};

		std::list<disable_token> tokens;
	};

	intfconf_list m_intfconfs;

	class group_configuration : public ptree<inet6_addr, groupconf> {
	public:
		groupconf *create_child(const inet6_addr &);
		groupconf *match(const inet6_addr &, const groupconf * = 0) const;
		void clear();
	};

	group_configuration m_routing_table;

	class groups_node : public node {
	public:
		groups_node(node *);

		node *get_child(const char *) const;
		node *create_child(const char *);
	};

	groups_node m_groups_node;

	typedef std::list<event_sink *> active_state_interest;
	active_state_interest m_active_state_interest;

	typedef std::list<socket_base *> socket_list;
	socket_list m_read, m_write;

	fd_set m_rdst, m_wrst;
	int m_largestsock;

	mfa_core *m_mfa;

	rib_def *m_rib_handler;
	icmp_base *m_icmp;

	typedef std::deque<task> tasks;
	tasks m_tasks;
	uint32_t m_tasks_stat;
	uint64_t m_tasks_time_spent;

	std::map<std::string, mrd_module *> m_modules;

	typedef mrd_module *module_init_sig(void *, mrd *);

	typedef std::map<std::string, module_init_sig *> static_modules;
	static_modules m_static_modules;

	typedef std::set<std::string> early_modules;
	early_modules m_early_modules;

	void event(int, void *);

	bool shutdown(base_stream &, const std::vector<std::string> &);
	bool show_version(base_stream &, const std::vector<std::string> &);
	bool show_timers(base_stream &, const std::vector<std::string> &);
	bool show_rpf(base_stream &, const std::vector<std::string> &);
	bool load_module(base_stream &, const std::vector<std::string> &);
	bool unload_module(base_stream &, const std::vector<std::string> &);
	bool unicast_regs(base_stream &, const std::vector<std::string> &);
	bool socket_regs(base_stream &, const std::vector<std::string> &);
	bool show_info(base_stream &, const std::vector<std::string> &);
	bool show_conf(base_stream &, const std::vector<std::string> &);

	void dump_node_tree(base_stream &, node *) const;
	void dump_node_tree(base_stream &, node *, std::vector<node *> &) const;

	int show_conf_node(base_stream &, node *, bool print) const;

	bool show_commands(base_stream &, const std::vector<std::string> &);
	void dump_commands(base_stream &, const node *, const std::string &) const;

	friend class log_base;
	friend class mfa_core;
};

inline interface *mrd::get_interface_by_index(int n) const {
	interface *possible = m_intf_cache[n & (_INTERFACE_CACHE_LEN-1)];

	if (possible && possible->index() == n)
		return possible;

	interface_list::const_iterator p = m_intflist.find(n);
	if (p == m_intflist.end())
		return 0;

	m_intf_cache[n & (_INTERFACE_CACHE_LEN-1)] = p->second;

	return p->second;
}

inline bool mrd::interest_in_active_states() const {
	return !m_active_state_interest.empty();
}

/*!
 * mrd modules implement mrd_module
 */
class mrd_module {
public:
	mrd_module(mrd *, void *);
	virtual ~mrd_module();

	virtual bool check_startup() = 0;
	virtual void shutdown() {}

	virtual void module_loaded(const char *, mrd_module *) {}

protected:
	void *m_dlhandle;
	mrd *m_mrd;

	friend class mrd;
};

#define module_entry(x, y) \
	extern "C" mrd_module *mrd_module_init_##x(void *dlh, mrd *m) { \
		return new y (m, dlh); \
	}

extern mrd *g_mrd;

#endif


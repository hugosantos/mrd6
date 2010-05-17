/*
 * Multicast Routing Daemon (MRD)
 *   interface.h
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

#ifndef _mrd_interface_h_
#define _mrd_interface_h_

#include <string>
#include <map>
#include <list>
#include <set>

#include <mrd/node.h>
#include <mrd/timers.h>

class mrd;
class router;
class intfconf;
class interface;
class base_stream;
class intfconf_node;

class intfconf : public conf_node {
public:
	typedef conf_node base;

	intfconf(const char *);
	~intfconf();

	const char *description() const { return "Interface configuration"; }

	bool check_startup();

	void fill_defaults();

	void property_changed(node *, const char *);
	node *create_child(const char *);
	bool call_method(int, base_stream &,
			 const std::vector<std::string> &);

	virtual node *next_similiar_node() const;

	bool is_enabled() const;

	bool is_router_enabled(const char *) const;

	void update_interface_configuration(interface *);

private:
	bool disable_router(const std::vector<std::string> &);
	void remove_child_node(node *);

	std::set<std::string> disabled_routers;
};

class intfconf_node : public conf_node {
public:
	intfconf_node(intfconf *, const char *);

	virtual bool fill_defaults() { return true; }
	virtual node *next_similiar_node() const;
};

class interface_node : public node {
public:
	interface_node(router *rt);
	virtual ~interface_node();

	virtual void attached(interface *owner);
	virtual void dettached();

	interface *owner() const { return n_owner; }
	router *owner_router() const { return n_owner_router; }

	virtual void address_added_or_removed(bool, const inet6_addr &) {}

	/* logging */
	bool should_log(int) const;
	base_stream &log() const;

protected:
	interface *n_owner;
	router *n_owner_router;
};

/*!
 * \class interface mrd/interface.h
 * \brief Represents a system network interface.
 */
class interface : public node {
public:
	interface(intfconf *, int indx, const char *name, int type, int mtu, int flags);
	~interface();

	void shutdown();

	int index() const { return mif_index; }
	const char *name() const { return mif_name.c_str(); }

	const char *description() const { return "Network interface"; }

	enum {
		None = 0,
		Loopback,
		Ethernet,
		PPP,
		Tunnel,
		TUN,
		IEEE1394,
		IEEE802_11,
		IEEE802_1Q,
		IPv4_Translator,
	};

	enum kernel_state {
		Down,
		NoLink,
		Up,
	};

	int type() const { return mif_type; }
	const char *type_str() const;
	int mtu() const { return mif_mtu; }

	kernel_state state() const { return mif_state; }

	bool up(bool ignoremrd = false) const;

	void change_state(kernel_state);

	/* Is the interface a virtual interface? */
	bool is_virtual();

	/* returns true if this interface is attached
	 * to a multi-access LAN */
	bool is_multiaccess() const;

	bool attach_node(interface_node *);
	void dettach_node(interface_node *);
	interface_node *node_owned_by(const router *) const;

	const in6_addr *linklocal() const { return mif_linklocal.address_p(); }

	const std::set<inet6_addr> &linklocals() const { return mif_linklocals; }
	const std::set<inet6_addr> &globals() const { return mif_globals; }

	const inet6_addr &primary_addr() const;

	const sockaddr_in6 *localaddr() const { return &mif_localaddr; }

	bool has_global(const in6_addr &addr) const;

	bool in_same_subnet(const in6_addr &) const;

	intfconf *conf() const { return mif_conf; }

	void address_added_or_removed(bool isnew, const inet6_addr &);

	bool output_info(base_stream &, const std::vector<std::string> &) const;
	base_stream &log() const;

private:
	friend class mrd;
	friend class intfconf;

	int mif_index;
	std::string mif_name;
	int mif_type;
	int mif_mtu;
	int mif_flags;

	kernel_state mif_state;
	bool mif_enabled;

	sockaddr_in6 mif_localaddr;
	inet6_addr mif_linklocal;

	std::set<inet6_addr> mif_linklocals;
	std::set<inet6_addr> mif_globals;

	intfconf *mif_conf;

	tval mif_creationtime;

	void add_remove_address(bool isnew, const inet6_addr &);
	void broadcast_change_state(bool wasdown);
	void set_enabled(bool);
};

uint16_t ipv6_checksum(uint8_t protocol, const in6_addr &src, const in6_addr &dst, const void *data, uint16_t len);

#endif


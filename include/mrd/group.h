/*
 * Multicast Routing Daemon (MRD)
 *   group.h
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

#ifndef _mrd_group_h_
#define _mrd_group_h_

#include <map>

#include <mrd/node.h>
#include <mrd/timers.h>
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/address_set.h>
#include <mrd/packet_buffer.h>
#include <mrd/source_discovery.h>

#include <mrd/support/ptree.h>

class group;
class group_node;
class group_interface;
class groupconf_node;

class router;

/*!
 * base group configuration node which provides configuration
 * aggregation to active groups
 */
class groupconf : public ptree_node, public conf_node {
public:
	groupconf(const inet6_addr &);
	~groupconf();

	const char *description() const { return "Group configuration"; }

	bool check_startup();

	void fill_defaults();

	const inet6_addr &id() const { return prefix; }

	bool call_method(int, base_stream &,
			 const std::vector<std::string> &);

	node *create_child(const char *);

	virtual node *next_similiar_node() const;

	typedef std::vector<std::string> source_discs;

	const source_discs &get_source_discs() const { return srcdisc; }

	void set_source_discs(const source_discs &);

	inet6_addr prefix;

private:
	void remove_child_node(node *n);

	source_discs srcdisc;

	friend class group;
};

class groupconf_node : public conf_node {
public:
	groupconf_node(groupconf *, const char *);
	virtual ~groupconf_node() {}

	virtual bool fill_defaults() { return true; }
	node *next_similiar_node() const;
};

/*!
 * for each group, there is a group_interface which contains that
 * contains the corresponding interface's state for the group
 * (filter list, filter mode, subscriber list, etc).
 */
class group_interface : public node {
public:
	group_interface(group *, group_node *, interface *);
	virtual ~group_interface();

	const char *description() const { return "Multicast group local interface"; }

	virtual void shutdown();

	/*!
	 * returns the owner group instance.
	 */
	group *owner() const { return g_owner; }

	group_node *owner_node() const { return g_node_owner; }

	/*!
	 * returns the corresponding network interface.
	 */
	interface *intf() const { return g_intf; }

	enum event_type {
		added_sources = 1,
		removed_sources = 2,
		all_sources = 3
	};

	enum filter_mode_type {
		include = 1,
		exclude = 2
	};

	filter_mode_type filter_mode() const { return g_filter_mode; }

	const address_set &include_set() const { return g_include_set; }
	const address_set &exclude_set() const { return g_exclude_set; }

	const address_set &active_set() const;

	bool has_interest_on(const in6_addr &) const;

	void dump_filter(base_stream &) const;

	bool output_info(base_stream &, const std::vector<std::string> &) const;
	virtual void output_info(base_stream &, bool detailed) const;

	bool should_log(int) const;
	base_stream &log() const;

protected:
	void dump_filter() const;

	group *g_owner;
	group_node *g_node_owner;
	interface *g_intf;

	filter_mode_type g_filter_mode;
	address_set g_include_set, g_exclude_set;
};

/*!
 * each implemented protocol (PIM, etc) implements a group_node to receive
 * group information, such as changes in the subscriber list.
 */
class group_node : public node {
public:
	group_node(router *rt);
	virtual ~group_node();

	virtual void attached(group *owner);
	virtual void dettached();

	group *owner() const { return g_owner; }
	router *owner_router() const { return g_owner_router; }

	virtual void subscriptions_changed(const group_interface *,
			group_interface::event_type, const address_set &);

	virtual void discovered_source(interface *input, const inet6_addr &,
				       source_discovery_origin *);
	virtual void lost_source(const inet6_addr &, source_discovery_origin *);

	virtual void clear_interface_references(interface *) {}
	virtual group_interface *instantiate_group_interface(interface *intf)
		{ return 0; }

	virtual bool has_interest_in_group() const { return false; }
	virtual bool has_downstream_interest(const in6_addr &) const { return false; }

	bool should_log(int) const;
	base_stream &log() const;

protected:
	group *g_owner;
	router *g_owner_router;
};

/*!
 * implements the base group concept node.
 */
class group : public node {
public:
	group(const inet6_addr &, groupconf *);
	virtual ~group();

	const char *description() const { return "Active multicast group"; }

	bool check_startup();
	void shutdown();

	bool attach_node(group_node *);
	void dettach_node(group_node *);
	group_node *node_owned_by(const router *) const;

	groupconf *conf() const { return g_conf; }

	group_interface *local_oif(int) const;
	group_interface *local_oif(interface *);

	bool has_interest_on(const in6_addr &) const;
	bool has_downstream_interest(const in6_addr &) const;

	const inet6_addr &id() const { return g_addr; }

	void clear_interface_references(interface *);

	typedef std::map<int, group_interface *> group_intfs;

	const group_intfs &interface_table() const { return g_oifs; }

	void trigger_mode_event(group_interface *, group_interface::event_type,
				const address_set &) const;

	void discovered_source(interface *, const inet6_addr &,
			       source_discovery_origin *) const;
	void lost_source(const inet6_addr &, source_discovery_origin *) const;

	bool someone_lost_interest();

	bool output_info(base_stream &, const std::vector<std::string> &) const;

	void broadcast_source_interest_change(group_node *, bool include = true) const;

	base_stream &log() const;

protected:
	void broadcast_source_interest_change(groupconf *,
						group_node *, bool) const;

	bool output_info(base_stream &, bool detailed) const;

	bool is_group_node(const property_def &) const;

	groupconf *groupconf_with_sourcedisc() const;

	inet6_addr g_addr;
	groupconf *g_conf;

	bool g_doomed;

	group_intfs g_oifs;

	node g_intflist;

	friend class mrd;
};

#endif


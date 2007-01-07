/*
 * Multicast Routing Daemon (MRD)
 *   group.cpp
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

#include <mrd/group.h>
#include <mrd/interface.h>
#include <mrd/mrd.h>
#include <mrd/address.h>
#include <mrd/router.h>

#include <string>
#include <stdarg.h>

enum {
	static_sources_method_static = 1000,
	static_sources_method_remove
};

static const method_info static_sources_methods[] = {
	{ "static", "Adds a static source entry",
		static_sources_method_static, false, 0 },
	{ "remove", "Removes a static source entry",
		static_sources_method_remove, false, 0 },
	{ 0 }
};

enum {
	groupconf_method_source_discovery = 1000
};

static const method_info groupconf_methods[] = {
	{ "source-discovery", "Specifies the source discovery origins to use for this group conf.",
		groupconf_method_source_discovery, false, 0 },
	{ 0 }
};

class _static_sources_node : public node {
public:
	_static_sources_node(node *parent, source_discovery_origin *origin);

	bool check_startup();

	void group_interest_changed(group_node *n, bool include,
				    static_source_discovery *);

	bool call_method(int, base_stream &,
			 const std::vector<std::string> &);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

private:
	address_set sources;
	source_discovery_origin *origin;
};

_static_sources_node::_static_sources_node(node *parent, source_discovery_origin *o)
	: node(parent, "sources"), origin(o) {}

bool _static_sources_node::check_startup() {
	if (!node::check_startup())
		return false;
	import_methods(static_sources_methods);
	return true;
}

void _static_sources_node::group_interest_changed(group_node *n, bool include,
						static_source_discovery *origin) {
	for (address_set::const_iterator i = sources.begin();
			i != sources.end(); ++i) {
		if (include) {
			n->discovered_source(0, *i, origin);
		} else {
			n->lost_source(*i, origin);
		}
	}
}

bool _static_sources_node::call_method(int id, base_stream &out,
				       const std::vector<std::string> &args) {
	switch (id) {
	case static_sources_method_static:
	case static_sources_method_remove:
		if (args.empty())
			return false;

		std::vector<inet6_addr> addrs;

		for (std::vector<std::string>::const_iterator i =
				args.begin(); i != args.end(); ++i) {
			inet6_addr addr;
			if (!addr.set(*i))
				return false;
			addrs.push_back(addr);
		}

		bool add = (id == static_sources_method_static);

		groupconf *owner = (groupconf *)parent();

		for (std::vector<inet6_addr>::const_iterator i =
				addrs.begin(); i != addrs.end(); ++i) {
			if (add) {
				if (sources.insert(*i).second)
					origin->discovered_source(0, owner->id(), *i);
			} else {
				if (sources.remove(*i))
					origin->lost_source(owner->id(), *i);
			}
		}

		return true;
	}

	return node::call_method(id, out, args);
}

bool _static_sources_node::output_info(base_stream &os, const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	os.xprintf("Sources: %{addrset}\n", sources);

	return true;
}

source_discovery_origin::~source_discovery_origin() {
}

void source_discovery_origin::discovered_source(int ifindex,
						const inet6_addr &groupmask,
						const inet6_addr &source) {
	g_mrd->discovered_source(ifindex, groupmask, source, this);
}

void source_discovery_origin::lost_source(const inet6_addr &groupmask,
						const inet6_addr &source) {
	g_mrd->lost_source(groupmask, source, this);
}

void source_discovery_origin::group_interest_changed(group_node *, bool include) {
}

void source_discovery_origin::groupconf_registered(groupconf *, bool) {
}

aggr_source_discovery::aggr_source_discovery(int keepalive)
	: m_keepalive(keepalive),
	  m_gc_timer("source disc gc", this, std::mem_fun(&aggr_source_discovery::gc)) {}

bool aggr_source_discovery::check_startup() {
	m_gc_timer.start(5000, true);

	return true;
}

void aggr_source_discovery::discovered_source(int ifindex,
					      const inet6_addr &group,
					      const inet6_addr &src) {
	/* if it wasn't in the cache or was old*/
	if (add_to_cache(m_cache, ifindex, group, src) >= 0)
		source_discovery_origin::discovered_source(ifindex, group, src);
}

int aggr_source_discovery::add_to_cache(cache &c, int ifindex,
					const inet6_addr &group,
					const inet6_addr &src) {
	sg_pair p(group, src);

	cache::iterator i = c.find(p);

	time_t now = time(0);

	if (i == c.end()) {
		c.insert(std::make_pair(p, now));

		if (g_mrd->should_log(INTERNAL_FLOW)) {
			g_mrd->log().xprintf("AggrSourceDiscovery added source"
					     " (%{Addr}, %{Addr}) to cache.\n",
					     src, group);
		}

		return 1;
	} else {
		if ((now - i->second) > m_keepalive) {
			if (g_mrd->should_log(INTERNAL_FLOW)) {
				g_mrd->log().xprintf("AggrSourceDiscovery "
						     "updated source (%{Addr},"
						     "%{Addr}), cache was old.\n",
						     src, group);
			}

			/* was in the cache but is old */
			source_discovery_origin::discovered_source(ifindex, group, src);

			return 0;
		}

		i->second = now;
	}

	return -1;
}

void aggr_source_discovery::lost_source(const inet6_addr &group,
					const inet6_addr &src) {
	cache::iterator i = m_cache.find(sg_pair(group, src));
	if (i != m_cache.end()) {
		m_cache.erase(i);
	}

	source_discovery_origin::lost_source(group, src);
}

void aggr_source_discovery::group_interest_changed(group_node *n, bool include) {
	if (!n || !include)
		return;

	cache::iterator i = m_cache.begin();

	while (i != m_cache.end()) {
		cache::iterator j = i;
		++i;

		if (n->owner()->id() == j->first.first)
			m_cache.erase(j);
	}
}

void aggr_source_discovery::dump_cache(base_stream &out) const {
	out.writeline("Source cache");

	out.inc_level();

	dump_cache(out, m_cache);

	out.dec_level();
}

void aggr_source_discovery::dump_cache(base_stream &out, const cache &c) const {
	time_t now = time(0);

	for (cache::const_iterator i = c.begin(); i != c.end(); ++i) {
		out.xprintf("(%{Addr}, %{Addr}) for %{duration}\n",
			    i->first.second, i->first.first,
			    time_duration((now - i->second) * 1000));
	}
}

void aggr_source_discovery::gc() {
	run_gc(m_cache);
}

void aggr_source_discovery::run_gc(cache &c) {
	time_t now = time(0);

	cache::iterator i = c.begin();

	while (i != c.end()) {
		cache::iterator j = i;
		++i;

		if ((now - j->second) > m_keepalive) {
			if (g_mrd->should_log(INTERNAL_FLOW)) {
				g_mrd->log().xprintf("AggrSourceDiscovery "
					"cleaned source (%{Addr}, %{Addr}).\n",
					j->first.second, j->first.first);
			}

			c.erase(j);
		}
	}
}

data_plane_source_discovery::data_plane_source_discovery()
	: aggr_source_discovery(30) {}

void static_source_discovery::group_interest_changed(group_node *n, bool include) {
	if (!n)
		return;

	groupconf *gc = n->owner()->conf();

	while (gc) {
		if (gc->get_child("sources"))
			break;
		gc = (groupconf *)gc->next_similiar_node();
	}

	if (!gc) {
		return;
	}

	_static_sources_node *sources = (_static_sources_node *)gc->get_child("sources");
	if (!sources)
		return;

	sources->group_interest_changed(n, include, this);
}

void static_source_discovery::groupconf_registered(groupconf *gc, bool include) {
	if (include) {
		_static_sources_node *sources = new _static_sources_node(gc, this);
		if (!sources || !sources->check_startup()) {
			delete sources;
			return;
		}

		gc->add_child(sources);
	} else {
		node *n = gc->get_child("sources");
		if (n) {
			gc->remove_child("sources");
			delete n;
		}
	}
}

source_discovery_sink::~source_discovery_sink() {
	/* empty */
}

void source_discovery_sink::discovered_source(interface *input,
					      const inet6_addr &groupaddr,
					      const inet6_addr &sourceaddr,
					      source_discovery_origin *origin) {
	group *gr = g_mrd->get_group_by_addr(groupaddr);
	if (gr)
		discovered_source(input, gr, sourceaddr, origin);
}

void source_discovery_sink::discovered_source(interface *input, group *,
					      const inet6_addr &,
					      source_discovery_origin *origin) {
	/* empty */
}

groupconf::groupconf(const inet6_addr &addr)
	: conf_node(g_mrd->get_child("groups"), addr.as_string().c_str()), prefix(addr) {
}

groupconf::~groupconf() {
	clear_childs();
}

bool groupconf::check_startup() {
	if (!conf_node::check_startup())
		return false;

	import_methods(groupconf_methods);

	return true;
}

void groupconf::fill_defaults() {
	srcdisc.push_back("data-plane");

	for (properties::iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (i->second.is_child()) {
			((groupconf_node *)i->second.get_node())->fill_defaults();
		}
	}
}

node *groupconf::next_similiar_node() const {
	return g_mrd->get_similiar_groupconf_node(this);
}

bool groupconf::call_method(int id, base_stream &out,
			    const std::vector<std::string> &args) {
	switch (id) {
	case groupconf_method_source_discovery:
		for (std::vector<std::string>::const_iterator j =
				srcdisc.begin(); j != srcdisc.end(); ++j) {
			std::vector<std::string>::const_iterator k =
				std::find(args.begin(), args.end(), *j);

			if (k == args.end()) {
				source_discovery_origin *origin =
					g_mrd->get_source_discovery(j->c_str());
				if (origin)
					origin->groupconf_registered(this, false);
			}
		}

		srcdisc = args;

		for (std::vector<std::string>::const_iterator j =
				srcdisc.begin(); j != srcdisc.end(); ++j) {
			source_discovery_origin *origin =
				g_mrd->get_source_discovery(j->c_str());
			if (origin)
				origin->groupconf_registered(this, true);
		}

		return true;
	}

	return conf_node::call_method(id, out, args);
}

node *groupconf::create_child(const char *name) {
	node *child = get_child(name);
	if (child)
		return child;

	router *rt = g_mrd->get_router(name);
	if (rt)
		child = rt->create_group_configuration(this);

	if (!child || !child->check_startup()) {
		delete child;
		return 0;
	}

	add_child(child, false, name);

	return child;
}

void groupconf::remove_child_node(node *_n) {
	delete (groupconf_node *)_n;
}

void groupconf::set_source_discs(const source_discs &d) {
	srcdisc = d;
}

groupconf_node::groupconf_node(groupconf *parent, const char *name)
	: conf_node(parent, name) {}

node *groupconf_node::next_similiar_node() const {
	node *curr = parent();

	while ((curr = curr->next_similiar_node())) {
		node *child = curr->get_child(name());
		if (child)
			return child;
	}

	return 0;
}

group_interface::group_interface(group *grp, group_node *n, interface *i)
	: node(grp, i->name()), g_owner(grp), g_node_owner(n), g_intf(i), g_filter_mode(include) {
}

group_interface::~group_interface() {
}

void group_interface::shutdown() {
	g_filter_mode = include;
	g_include_set.clear();
	g_exclude_set.clear();

	owner()->trigger_mode_event(this, all_sources, address_set());
}

bool group_interface::has_interest_on(const in6_addr &addr) const {
	if (g_filter_mode == include)
		return g_include_set.has_addr(addr);
	else
		return !g_exclude_set.has_addr(addr);
}

void group_interface::dump_filter(base_stream &os) const {
	os.xprintf("%s %{addrset}",
		   (filter_mode() == include ? "Include" : "Exclude"),
		   (filter_mode() == include ? include_set() : exclude_set()));
}

void group_interface::dump_filter() const {
	if (should_log(DEBUG)) {
		base_stream &os = log();

		os.write("Filter is now ");
		dump_filter(os);
		os.newl();
	}
}

const address_set &group_interface::active_set() const {
	if (g_filter_mode == include)
		return include_set();
	else
		return exclude_set();
}

bool group_interface::output_info(base_stream &out, const std::vector<std::string> &args) const {
	output_info(out, false);
	return true;
}

void group_interface::output_info(base_stream &, bool) const {
}

bool group_interface::should_log(int level) const {
	return owner_node()->should_log(level) && intf()->should_log(level);
}

base_stream &group_interface::log() const {
	return intf()->log().xprintf("(%{Addr}) ", owner()->id());
}

group_node::group_node(router *rt)
	: node(0, rt->name()), g_owner(0), g_owner_router(rt) {}

group_node::~group_node() {
}

void group_node::attached(group *owner) {
	m_parent = owner;
	g_owner = owner;
}

void group_node::dettached() {
	m_parent = 0;
	g_owner = 0;
}

void group_node::subscriptions_changed(const group_interface *,
				group_interface::event_type,
				const address_set &) {
}

void group_node::discovered_source(interface *, const inet6_addr &,
				   source_discovery_origin *) {
	/* empty */
}

void group_node::lost_source(const inet6_addr &,
				source_discovery_origin *) {
}

bool group_node::should_log(int level) const {
	if (owner() && owner()->should_log(level))
		return owner_router() && owner_router()->should_log(level);
	return false;
}

base_stream &group_node::log() const {
	return owner_router()->log_router_desc(owner()->log());
}

group::group(const inet6_addr &addr, groupconf *conf)
	: node(g_mrd->get_child("group"), addr.as_string().c_str()),
		g_addr(addr), g_conf(conf),
		g_intflist(this, "interfaces") {

	g_doomed = false;

	add_child(&g_intflist);
}

group::~group() {
	for (group_intfs::iterator j = g_oifs.begin(); j != g_oifs.end(); j++) {
		delete j->second;
	}

	for (properties::iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (is_group_node(i->second))
			delete i->second.get_node();
	}
}

bool group::check_startup() {
	return node::check_startup();
}

void group::shutdown() {
	for (group_intfs::iterator j = g_oifs.begin(); j != g_oifs.end(); j++) {
		delete j->second;
	}
	g_oifs.clear();

	properties::iterator i = m_properties.begin();

	while (i != m_properties.end()) {
		properties::iterator j = i;
		++i;

		if (is_group_node(j->second))
			dettach_node((group_node *)j->second.get_node());
	}
}

bool group::output_info(base_stream &_out, bool detailed) const {
	_out.xprintf("Group %{Addr}\n", id());

	_out.inc_level();

	node::output_info(_out, std::vector<std::string>());

	_out.dec_level();

	return true;
}

bool group::output_info(base_stream &out, const std::vector<std::string> &args) const {
	bool detailed = false;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		if (*i == "detail")
			detailed = true;
		else
			return false;
	}

	return output_info(out, detailed);
}

bool group::is_group_node(const property_def &prop) const {
	return prop.is_child() && prop.get_node() != &g_intflist;
}

groupconf *group::groupconf_with_sourcedisc() const {
	groupconf *gc = conf();

	while (gc) {
		if (!gc->srcdisc.empty())
			break;
		gc = (groupconf *)gc->next_similiar_node();
	}

	return gc;
}

bool group::attach_node(group_node *node) {
	add_child(node);
	node->attached(this);

	broadcast_source_interest_change(groupconf_with_sourcedisc(),
					 node, true);

	return true;
}

void group::dettach_node(group_node *node) {
	group_node *n = (group_node *)get_child(node->name());

	if (n && n == node) {
		broadcast_source_interest_change(groupconf_with_sourcedisc(),
						 node, false);

		remove_child(node->name());
		node->dettached();
	}
}

group_node *group::node_owned_by(const router *rt) const {
	return (group_node *)get_child(rt->name());
}

group_interface *group::local_oif(int index) const {
	group_intfs::const_iterator i = g_oifs.find(index);

	if (i != g_oifs.end())
		return i->second;

	return 0;
}

group_interface *group::local_oif(interface *intf) {
	group_intfs::const_iterator i = g_oifs.find(intf->index());

	if (i != g_oifs.end())
		return i->second;

	group_interface *oif = 0;

	if (conf()->has_property("group-intf")) {
		const char *val = conf()->get_property_string("group-intf");

		if (val) {
			properties::iterator i = m_properties.find(val);

			if (i != m_properties.end()) {
				group_node *gn =
					(group_node *)i->second.get_node();

				if (gn)
					oif = gn->instantiate_group_interface(intf);
			}
		}
	}

	if (!oif) {
		for (properties::iterator j = m_properties.begin();
				!oif && j != m_properties.end(); ++j) {
			if (is_group_node(j->second)) {
				group_node *gn =
					(group_node *)j->second.get_node();

				oif = gn->instantiate_group_interface(intf);
			}
		}
	}

	// if no group node is interested in handling this interface
	// we instantiate a default group_interface
	if (!oif)
		oif = new group_interface(this, 0, intf);

	if (oif) {
		if (should_log(VERBOSE)) {
			log().xprintf("Added %s to interface list.\n",
				      intf->name());
		}

		g_oifs.insert(std::make_pair(intf->index(), oif));

		/* XXX if the interface gets renamed.. this will bork */
		g_intflist.add_child(oif, false, intf->name());
	}

	return oif;
}

void group::clear_interface_references(interface *intf) {
	group_intfs::iterator k = g_oifs.find(intf->index());

	/* First let's change the local interest to INCLUDE {} */
	if (k != g_oifs.end()) {
		k->second->shutdown();

		g_intflist.remove_child(intf->name());

		delete k->second;
		g_oifs.erase(k);
	}

	properties::iterator i = m_properties.begin();

	while (i != m_properties.end()) {
		properties::iterator j = i;
		++i;

		if (!is_group_node(j->second))
			continue;

		group_node *gn = (group_node *)j->second.get_node();

		gn->clear_interface_references(intf);
	}
}

void group::trigger_mode_event(group_interface *intf,
				group_interface::event_type event,
				const address_set &addrs) const {
	groupconf *conf = groupconf_with_sourcedisc();

	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (is_group_node(i->second)) {
			group_node *gnode = (group_node *)i->second.get_node();

			gnode->subscriptions_changed(intf, event, addrs);

			broadcast_source_interest_change(conf, gnode, true);
		}
	}
}

void group::broadcast_source_interest_change(group_node *gnode, bool in) const {
	broadcast_source_interest_change(groupconf_with_sourcedisc(), gnode, in);
}

void group::broadcast_source_interest_change(groupconf *conf, group_node *gnode,
					     bool in) const {
	if (conf) {
		for (std::vector<std::string>::const_iterator i =
			conf->srcdisc.begin(); i != conf->srcdisc.end(); ++i) {

			source_discovery_origin *origin = g_mrd->get_source_discovery(i->c_str());
			if (origin) {
				origin->group_interest_changed(gnode, in);
			}
		}
	}
}

void group::discovered_source(interface *input, const inet6_addr &source,
			      source_discovery_origin *origin) const {
	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (is_group_node(i->second)) {
			group_node *gn = (group_node *)i->second.get_node();

			gn->discovered_source(input, source, origin);
		}
	}
}

void group::lost_source(const inet6_addr &source,
			source_discovery_origin *origin) const {
	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (is_group_node(i->second)) {
			group_node *gn = (group_node *)i->second.get_node();

			gn->lost_source(source, origin);
		}
	}
}

bool group::has_interest_on(const in6_addr &src) const {
	for (group_intfs::const_iterator i = g_oifs.begin(); i != g_oifs.end(); i++) {
		if (((group_interface *)i->second)->has_interest_on(src))
			return true;
	}

	return false;
}

bool group::has_downstream_interest(const in6_addr &src) const {
	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (!is_group_node(i->second))
			continue;

		group_node *gn = (group_node *)i->second.get_node();

		if (gn->has_downstream_interest(src))
			return true;
	}

	return false;
}

bool group::someone_lost_interest() {
	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (!is_group_node(i->second))
			continue;

		group_node *grpnode = (group_node *)i->second.get_node();

		if (grpnode->has_interest_in_group()) {
			/*
			g_mrd->log().info(EXTRADEBUG) << "not removing group as "
				<< grpnode->owner_router()->name()
				<< " still has interest" << endl;
			*/
			return false;
		}
	}

	if (!g_doomed) {
		g_doomed = true;
		g_mrd->register_task(mrd::make_task(g_mrd, mrd::RemoveGroup, this));
	}

	return true;
}

base_stream &group::log() const {
	return node::log().xprintf("(%{Addr}) ", id());
}


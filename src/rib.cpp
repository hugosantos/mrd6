/*
 * Multicast Routing Daemon (MRD)
 *   rib.cpp
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

enum {
	rib_method_lookup = 4000,
};

static const method_info rib_methods[] = {
	{ "lookup", 0, rib_method_lookup, true, 0 },
	{ 0 }
};

rib_watcher_base::rib_watcher_base()
	: valid(false), dev(0), dst(in6addr_any), gateway(in6addr_any),
	  prefsrc(in6addr_any), protocol(0xffffffff), metric(0xffffffff) {}

rib_watcher_base::~rib_watcher_base() {
	release();
}

void rib_watcher_base::set_destination(const inet6_addr &target) {
	g_mrd->rib().register_route(this, target);
}

void rib_watcher_base::release() {
	g_mrd->rib().unregister_route(this);
}

rib_def::rib_def()
	: node(g_mrd, "rib") {
	populate_mrib = instantiate_property_b("populate-mrib", true);
	base_distance = instantiate_property_u("base-mrib-distance", 100);
}

bool rib_def::check_startup() {
	if (!node::check_startup())
		return false;

	import_methods(rib_methods);

	if (!populate_mrib || !base_distance)
		return false;

	return true;
}

void rib_def::shutdown() {
	g_mrd->mrib().origin_lost(this);
}

void rib_def::check_initial_interfaces() {
	/* empty */
}

const char *rib_def::description() const {
	return "RIB";
}

void rib_def::return_prefix(mrib_def::prefix *p) {
	delete p;
}

bool rib_def::dump_info(base_stream &os) const {
	for (notify_list::const_iterator i = rt_notify_list.begin();
				i != rt_notify_list.end(); ++i) {
		os.xprintf("%{addr}\n", i->first);
	}

	return true;
}

bool rib_def::call_method(int id, base_stream &out, const std::vector<std::string> &args) {
	if (id == rib_method_lookup) {
		if (args.empty())
			return false;

		inet6_addr dst, nh, src;

		if (!dst.set(args[0].c_str()))
			return false;

		interface *intf = path_towards(dst, nh, src);
		if (intf) {
			out.xprintf("Output interface is %s, nexthop is %{Addr} "
				    "(from %{Addr})\n", intf->name(), nh, src);
		} else {
			out.writeline("No path.");
		}
	} else {
		return node::call_method(id, out, args);
	}

	return true;
}

interface *rib_def::path_towards(const inet6_addr &dst) const {
	inet6_addr a, b, c;

	return path_towards(dst, a, b, c);
}

interface *rib_def::path_towards(const inet6_addr &dst, inet6_addr &a) const {
	inet6_addr b, c;

	return path_towards(dst, a, b, c);
}

interface *rib_def::path_towards(const inet6_addr &dst, inet6_addr &a, inet6_addr &b) const {
	inet6_addr c;

	return path_towards(dst, a, b, c);
}

interface *rib_def::path_towards(const inet6_addr &dst, inet6_addr &a, inet6_addr &b, inet6_addr &c) const {
	lookup_result res;

	if (lookup_prefix(dst, res)) {
		a = res.source;
		b = res.nexthop;
		c = res.dst;

		return g_mrd->get_interface_by_index(res.dev);
	}

	return 0;
}

void rib_def::update_route(rib_watcher_base *watch) {
	if (IN6_IS_ADDR_UNSPECIFIED(&watch->dst))
		return;

	lookup_result result;

	bool wasvalid = watch->valid;

	uint32_t changedflags = 0;

	if (lookup_prefix(watch->dst, result)) {
		watch->valid = true;

		if (wasvalid) {
			if (result.dev != watch->dev)
				changedflags |= rib_watcher_base::DEV;
			if (!(result.nexthop == watch->gateway))
				changedflags |= rib_watcher_base::GATEWAY;
			if (!(result.source == watch->prefsrc))
				changedflags |= rib_watcher_base::PREFSRC;
			if (!(result.protocol == watch->protocol))
				changedflags |= rib_watcher_base::PROTOCOL;
			if (!(result.metric == watch->metric))
				changedflags |= rib_watcher_base::METRIC;
		} else {
			changedflags = 0xffffffff;
		}

		watch->dev = result.dev;
		watch->gateway = result.nexthop;
		watch->prefsrc = result.source;
		watch->protocol = result.protocol;
		watch->metric = result.metric;
	} else {
		watch->valid = false;
		changedflags = wasvalid ? rib_watcher_base::HAS_ROUTE : 0;
	}

	if (changedflags)
		watch->route_changed(changedflags);
}

void rib_def::register_route(rib_watcher_base *watch, const inet6_addr &addr) {
	unregister_route(watch);

	watch->valid = false;
	watch->dst = addr;

	if (!addr.is_any()) {
		rt_notify_list.insert(std::make_pair(watch->dst, watch));

		update_route(watch);
	} else {
		watch->route_changed(rib_watcher_base::HAS_ROUTE);
	}
}

void rib_def::unregister_route(rib_watcher_base *watch) {
	notify_list::iterator i = rt_notify_list.lower_bound(watch->dst);

	while (i != rt_notify_list.end()) {
		if (i->second == watch) {
			rt_notify_list.erase(i);
			return;
		}

		if (i->first == watch->dst)
			++i;
		else
			break;
	}
}

void rib_def::transfer_watchers(rib_def *target) {
	target->rt_notify_list = rt_notify_list;

	rt_notify_list.clear();

	target->update_all();
}

void rib_def::update_all() {
	notify_list::iterator k = rt_notify_list.begin();

	while (k != rt_notify_list.end()) {
		notify_list::iterator j = k;
		++k;

		update_route(j->second);
	}
}

void rib_def::prefix_changed(bool isnew, const lookup_result &r) {
	notify_list::iterator k = rt_notify_list.begin();

	while (k != rt_notify_list.end()) {
		notify_list::iterator j = k;
		++k;

		if (r.dst.matches(j->first))
			update_route(j->second);
	}

	if (!populate_mrib->get_bool())
		return;

	/* don't feed multicast prefixes into MRIB */
	if (IN6_IS_ADDR_MULTICAST(&r.dst.addr))
		return;

	if (IN6_IS_ADDR_LINKLOCAL(&r.dst.addr))
		return;

	if (isnew) {
		interface *intf = g_mrd->get_interface_by_index(r.dev);
		if (!intf)
			return;

		mrib_def::prefix *p = new mrib_def::prefix(this);
		if (!p)
			return;

		p->distance = base_distance->get_unsigned() + r.protocol;
		p->metric = r.metric;
		p->intf = intf;
		p->nexthop = r.nexthop;
		p->flags = mrib_def::prefix::NO_EXPORT;

		if (!g_mrd->mrib().install_prefix(r.dst, p))
			delete p;
	} else {
		mrib_def::prefix *p = g_mrd->mrib().get_prefix(r.dst, this);
		if (p) {
			g_mrd->mrib().remove_prefix(p);
		}
	}
}


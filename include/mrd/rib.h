/*
 * Multicast Routing Daemon (MRD)
 *   rib.h
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

#ifndef _mrd_unicast_route_h_
#define _mrd_unicast_route_h_

#include <mrd/address.h>
#include <mrd/node.h>
#include <mrd/mrib.h>

#include <netinet/in.h>

class interface;

/*!
 * callback based unicast route watcher
 */
struct rib_watcher_base {
	rib_watcher_base();
	virtual ~rib_watcher_base();

	void set_destination(const inet6_addr &);
	void release();

	void update();

	enum {
		HAS_ROUTE = 1,
		GATEWAY = 2,
		PREFSRC = 4,
		DEV = 8,
		PROTOCOL = 16,
		METRIC = 32
	};

	virtual void route_changed(uint32_t) = 0;

	template<class T, class R>
	T *oif(R *r) const { return r->get_interface(dev); }

	bool valid;
	int dev;
	in6_addr dst, gateway, prefsrc;
	uint32_t protocol, metric;
};

/*!
 * template based unicast route watcher
 */
template<typename Holder>
struct rib_watcher : rib_watcher_base {
	typedef std::mem_fun1_t<void, Holder, uint32_t> callback_def;

	rib_watcher(Holder *, callback_def c);

	void route_changed(uint32_t);

private:
	Holder *_h;
	callback_def _cb;
};

template<typename H> inline rib_watcher<H>::rib_watcher(H *h,
				rib_watcher<H>::callback_def c)
	: rib_watcher_base(), _h(h), _cb(c) {}

template<typename H> inline void rib_watcher<H>::route_changed(uint32_t flags) {
	_cb(_h, flags);
}

/*!
 * provides an interface to get resolve unicast routes from
 * the operating system's RIB
 */
class rib_def : public node, public mrib_origin {
public:
	rib_def();

	virtual bool check_startup();
	virtual void shutdown();

	virtual void check_initial_interfaces();

	bool call_method(int, base_stream &, const std::vector<std::string> &);

	const char *description() const;
	void return_prefix(mrib_def::prefix *);

	virtual bool dump_info(base_stream &) const;

	virtual void register_route(rib_watcher_base *, const inet6_addr &);
	virtual void unregister_route(rib_watcher_base *);
	virtual void update_route(rib_watcher_base *);

	interface *path_towards(const inet6_addr &) const;
	interface *path_towards(const inet6_addr &, inet6_addr &) const;
	interface *path_towards(const inet6_addr &, inet6_addr &, inet6_addr &) const;
	interface *path_towards(const inet6_addr &addr, inet6_addr &prefsrc,
					inet6_addr &nexthop, inet6_addr &record) const;

	void transfer_watchers(rib_def *);

protected:
	typedef std::multimap<in6_addr, rib_watcher_base *> notify_list;

	notify_list rt_notify_list;

	struct lookup_result {
		int dev;
		inet6_addr dst;
		in6_addr nexthop, source;
		uint32_t protocol, metric;
	};

	virtual bool lookup_prefix(const in6_addr &, lookup_result &) const = 0;

	void update_all();
	void prefix_changed(bool, const lookup_result &);

	property_def *populate_mrib;
	property_def *base_distance;
};

#endif


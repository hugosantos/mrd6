/*
 * Multicast Routing Daemon (MRD)
 *   source_discovery.h
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

#ifndef _mrd_source_discovery_h_
#define _mrd_source_discovery_h_

#include <mrd/address.h>
#include <mrd/timers.h>

#include <map>
#include <time.h>

class group;
class group_node;
class groupconf;

/*!
 * Source discovery base interface. Source discovery origin's supply
 * new sources to mrd's core which are then distributed to source sinks
 * and group nodes, triggering the creation of source states.
 */
class source_discovery_origin {
public:
	virtual ~source_discovery_origin();

	/*!
	 * Returns the origin unique textual description. i.e. `static`,
	 * `data-plane`, etc.
	 */
	virtual const char *origin_description() const = 0;

	/*!
	 * may be called by source_discovery implementations in order to
	 * advertise a new source to all active groups that match the supplied
	 * group mask
	 */
	virtual void discovered_source(int ifindex, const inet6_addr &grpmask,
				       const inet6_addr &source);
	/*!
	 * may be called by source_discovery implementations in order to
	 * advertise that the supplied source was lost to all active groups
	 * that match the supplied group mask
	 */
	virtual void lost_source(const inet6_addr &groupmask,
				 const inet6_addr &source);

	/*!
	 * called by mrd whenever the interest of an active group on this
	 * source discovery origin changes. if include=true, the current
	 * known sources should be advertised via discovered_source
	 */
	virtual void group_interest_changed(group_node *, bool include);

	/*!
	 * called by mrd whenever this source discovery origin instance
	 * is attached to a group conf object. any childs and/or methods
	 * and properties should be instantiated here
	 */
	virtual void groupconf_registered(groupconf *, bool include);
};

class aggr_source_discovery : public source_discovery_origin {
public:
	bool check_startup();

	void discovered_source(int ifindex, const inet6_addr &groupmask,
			       const inet6_addr &source);
	void lost_source(const inet6_addr &groupmask,
				const inet6_addr &source);

	void group_interest_changed(group_node *n, bool include);

	void dump_cache(base_stream &) const;

protected:
	aggr_source_discovery(int keepalive);

	virtual void gc();

	typedef std::pair<inet6_addr, inet6_addr> sg_pair;
	typedef std::map<sg_pair, time_t> cache;

	int add_to_cache(cache &, int, const inet6_addr &, const inet6_addr &);
	void run_gc(cache &);

	void dump_cache(base_stream &, const cache &) const;

	int m_keepalive;
	cache m_cache;

	timer<aggr_source_discovery> m_gc_timer;
};

/*!
 * Data plane based source discovery implementation. Operating system
 * modules should instantiate a `data-plane` origin and call discovered_source()
 * for each non-existant state with active flows
 */
class data_plane_source_discovery : public aggr_source_discovery {
public:
	data_plane_source_discovery();

	const char *origin_description() const { return "data-plane"; }
};

/*!
 * Implements a static source origin. The sources to be advertised are populated
 * statically via configuration.
 */
class static_source_discovery : public source_discovery_origin {
public:
	const char *origin_description() const { return "static"; }

	void group_interest_changed(group_node *n, bool include);

	void groupconf_registered(groupconf *, bool include);
};

/*!
 * Registered source discovery sinks in mrd receive discovered_source events
 */
class source_discovery_sink {
public:
	virtual ~source_discovery_sink();

	/*!
	 * the default implementation checks if the group exists, and if
	 * so calls discovered_source with the group instance
	 */
	virtual void discovered_source(interface *, const inet6_addr &grpaddr,
				       const inet6_addr &sourceaddr,
				       source_discovery_origin *);

	virtual void discovered_source(interface *, group *,
				       const inet6_addr &source,
				       source_discovery_origin *);
};

#endif


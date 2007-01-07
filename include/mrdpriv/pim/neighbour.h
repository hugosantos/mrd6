/*
 * Multicast Routing Daemon (MRD)
 *   pim/neighbour.h
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

#ifndef _mrd_pim_neighbour_h_
#define _mrd_pim_neighbour_h_

#include <mrd/address.h>
#include <mrd/mrib.h>
#include <mrd/timers.h>

#include <list>
#include <map>

class pim_interface;
class pim_source_state_base;

class pim_neighbour;

struct pim_encoded_unicast_address;

class pim_neighbour_watcher_base : public mrib_watcher_base {
public:
	pim_neighbour_watcher_base(mrib_watcher_target *);
	virtual ~pim_neighbour_watcher_base();

	bool check_startup();

	bool self_upstream() const;

	bool recheck_neighbour();

	pim_neighbour *neigh() const { return w_neigh; }

	pim_interface *tentative_interface() const;

	uint32_t route_protocol() const;
	uint32_t route_metric() const;

	virtual void callback() = 0;

private:
	void entry_changed();

	pim_neighbour *w_neigh;
	pim_interface *w_lastintf;
};

inline uint32_t pim_neighbour_watcher_base::route_protocol() const {
	return mrib_watcher_base::prefix_protocol();
}

inline uint32_t pim_neighbour_watcher_base::route_metric() const {
	return mrib_watcher_base::prefix_metric();
}

template<typename Holder>
class pim_neighbour_watcher : public pim_neighbour_watcher_base {
public:
	typedef std::mem_fun1_t<void, Holder, pim_neighbour_watcher_base *> watcher_callback;

	pim_neighbour_watcher(Holder *, watcher_callback c, mrib_watcher_target *);

	void callback();

private:
	Holder *_h;
	watcher_callback _cb;
};

template<typename H> inline pim_neighbour_watcher<H>::pim_neighbour_watcher(H *h,
			watcher_callback c, mrib_watcher_target *t)
	: pim_neighbour_watcher_base(t), _h(h), _cb(c) {}

template<typename H> inline void pim_neighbour_watcher<H>::callback() {
	_cb(_h, this);
}

class pim_neighbour {
public:
	pim_neighbour(pim_interface *, const inet6_addr &);

	void shutdown();

	void set_present(bool);

	bool compare_genid(uint32_t) const;

	const inet6_addr &localaddr() const { return n_addr; }
	pim_interface *intf() const { return n_intf; }

	bool has_dr_priority() const { return n_flags & f_has_dr_priority; }
	uint32_t dr_priority() const { return n_dr_priority; }

	bool has_genid() const { return n_flags & f_has_genid; }
	uint32_t genid() const { return n_genid; }

	bool has_lan_delay() const { return n_flags & f_has_lan_delay; }
	uint32_t propagation_delay() const { return n_propagation_delay; }
	uint32_t override_interval() const { return n_override_interval; }

	bool tracking_support() const { return n_tracking_support; }

	uint32_t holdtime() const { return n_holdtimer.get_interval(); }

	const std::set<in6_addr> &secundary_addresses() const { return n_secaddrs; }

	void update_from_hello(pim_encoded_unicast_address *, int,
			       pim_encoded_unicast_address *, int, int);

	void set_holdtime(uint32_t);
	void set_dr_priority(uint32_t);
	void set_genid(uint32_t);
	void set_lan_delay(uint16_t, uint16_t, bool);

	bool has_address(const in6_addr &) const;

	class upstream_path {
	public:
		upstream_path(pim_neighbour *, pim_source_state_base *,
				const inet6_addr &target, bool wc, bool rpt);

		pim_neighbour *neigh() const { return p_neigh; }
		pim_source_state_base *state() const { return p_state; }
		const inet6_addr &target() const { return p_target; }
		bool wc() const { return p_wc; }
		bool rpt() const { return p_rpt; }

		void join(bool permanent);
		void prune(bool permanent);
		void remove(bool sendinvsingle = true);

		void send_single(bool supressholdtime) const;

		bool is_joined() const { return p_isjoin; }
		bool is_active() const { return p_active; }

		void refresh_now() const;
		void update_last_seen(uint32_t holdtime);

		bool may_be_overridden() const;

		void output_info(base_stream &) const;

	private:
		pim_neighbour *p_neigh;
		pim_source_state_base *p_state;
		inet6_addr p_target;
		bool p_wc, p_rpt;
		bool p_isjoin, p_active;
		tval p_last_seen;
		uint32_t p_last_seen_holdtime;
	};

	friend class upstream_path;

	upstream_path *add_path(pim_source_state_base *, const inet6_addr &, bool wc, bool rpt);
	void remove_path(upstream_path *);

	typedef timer1<pim_interface, pim_neighbour *> holdtimer;

	const holdtimer *get_holdtimer() const { return &n_holdtimer; }

	void output_info(base_stream &, bool extended) const;

	base_stream &log() const;

private:
	void handle_jp_timer();

	bool move_to_joins(upstream_path *);
	bool move_to_prunes(upstream_path *);

	pim_interface *n_intf;
	inet6_addr n_addr;
	holdtimer n_holdtimer;
	timer<pim_neighbour> n_jp_timer;

	bool n_present;

	uint32_t n_flags;
	uint32_t n_dr_priority;
	uint32_t n_genid;
	uint32_t n_propagation_delay, n_override_interval;
	bool n_tracking_support;

	enum {
		f_has_dr_priority = 1,
		f_has_genid = 2,
		f_has_lan_delay = 4
	};

	std::set<in6_addr> n_secaddrs;

	typedef std::list<upstream_path *> upstream_jp_state;

	struct group_state {
		upstream_jp_state joins, prunes;
	};

	typedef std::map<inet6_addr, group_state> upstream_state;

	upstream_state n_gstates;
	int npaths;
};

#endif


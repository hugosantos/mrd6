/*
 * Multicast Routing Daemon (MRD)
 *   pim_neighbour.cpp
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
#include <mrdpriv/pim/neighbour.h>
#include <mrdpriv/pim/interface.h>
#include <mrdpriv/pim/group.h>
#include <mrdpriv/pim/router.h>

pim_neighbour_watcher_base::pim_neighbour_watcher_base(mrib_watcher_target *t)
	: mrib_watcher_base(t) {
	w_lastintf = 0;
	w_neigh = 0;
}

pim_neighbour_watcher_base::~pim_neighbour_watcher_base() {
}

bool pim_neighbour_watcher_base::check_startup() {
	return true;
}

bool pim_neighbour_watcher_base::self_upstream() const {
	/* if we are the target or the nexthop, we are the upstream */
	if (g_mrd->has_address(target()) || g_mrd->has_address(nexthop()))
		return true;
	/* if the target is a known neighbour or the nexthop is a known neighbour,
	 * we aren't the upstream */
	if (pim->get_neighbour(target()) || pim->get_neighbour(nexthop()))
		return false;
	/* if the target is directly attached we are the upstream */
	return g_mrd->in_same_subnet(target());
}

static inline bool _in6_is_addr_unspecified(const in6_addr &addr) {
	return IN6_IS_ADDR_UNSPECIFIED(&addr);
}

bool pim_neighbour_watcher_base::recheck_neighbour() {
	pim_neighbour *last_neigh = w_neigh;

	bool self = self_upstream();

	w_neigh = 0;

	if (w_lastintf && !self && !_in6_is_addr_unspecified(nexthop())) {
		w_neigh = w_lastintf->get_neighbour(nexthop());
	}

	if (!w_neigh || last_neigh != w_neigh) {
		if (pim->should_log(EXTRADEBUG)) {
			base_stream &os =
				pim->log().xprintf("Neighbour for %{addr} "
						   "matched ", target());
			if (w_neigh)
				os.xprintf("%{Addr}", w_neigh->localaddr());
			else if (self)
				os.write("Self");
			else
				os.write("(None)");
			os.newl();
		}

		callback();

		return true;
	}

	return false;
}

pim_interface *pim_neighbour_watcher_base::tentative_interface() const {
	return w_lastintf;
}

void pim_neighbour_watcher_base::entry_changed() {
	pim_interface *lastintf = w_lastintf;

	if (pim->should_log(MESSAGE_SIG)) {
		base_stream &os = pim->log().xprintf("Neighbour for %{addr}",
						     target());
		if (intf())
			os.xprintf(" using interface %s", intf()->name());
		else
			os.write("has no path/interface");
		os.newl();
	}

	w_lastintf = pim->get_interface(intf());

	if (!recheck_neighbour() && lastintf != w_lastintf)
		callback();
}

pim_neighbour::pim_neighbour(pim_interface *i, const inet6_addr &t)
	: n_intf(i), n_addr(t),
	  n_holdtimer("pim neighbour timer", i, std::mem_fun(&pim_interface::neighbour_timed_out), this),
	  n_jp_timer("pim join/prune timer", this, std::mem_fun(&pim_neighbour::handle_jp_timer),
			  i->conf()->joinprune_interval(), true),
	  n_flags(0), npaths(0) {

	n_present = true;

	n_propagation_delay = 0;
	n_override_interval = 0;
	n_tracking_support = false;
}

void pim_neighbour::shutdown() {
	n_holdtimer.stop();
	n_jp_timer.stop();
}

void pim_neighbour::set_present(bool b) {
	n_present = b;
}

bool pim_neighbour::compare_genid(uint32_t genid) const {
	if (!(n_flags & f_has_genid))
		return true;
	return n_genid == genid;
}

void pim_neighbour::set_holdtime(uint32_t hold) {
	n_holdtimer.start_or_update(hold, false);
}

void pim_neighbour::set_dr_priority(uint32_t prio) {
	n_flags |= f_has_dr_priority;
	n_dr_priority = prio;
}

void pim_neighbour::set_genid(uint32_t gid) {
	n_flags |= f_has_genid;
	n_genid = gid;
}

void pim_neighbour::set_lan_delay(uint16_t progdelay, uint16_t overrinter, bool trackbit) {
	n_flags |= f_has_lan_delay;
	n_propagation_delay = progdelay;
	n_override_interval = overrinter;
	n_tracking_support = trackbit;
}

void pim_neighbour::update_from_hello(pim_encoded_unicast_address *addresses,
				      int address_count, pim_encoded_unicast_address *oldaddr,
				      int oldaddr_count, int holdtime) {
	int i;

	for (i = 0; i < address_count; i++) {
		n_secaddrs.insert(addresses[i].addr);
	}

	for (i = 0; i < oldaddr_count; i++) {
		n_secaddrs.insert(oldaddr[i].addr);
	}

	set_holdtime(holdtime * 1000);
}

bool pim_neighbour::has_address(const in6_addr &addr) const {
	if (n_addr == addr)
		return true;
	for (std::set<in6_addr>::const_iterator i = n_secaddrs.begin(); i != n_secaddrs.end(); ++i) {
		if (*i == addr)
			return true;
	}
	return false;
}

pim_neighbour::upstream_path *pim_neighbour::add_path(pim_source_state_base *state,
					const inet6_addr &target, bool wc, bool rpt) {
	if (intf()->should_log(MESSAGE_SIG)) {
		log().xprintf("add path for %{Addr} with target %{Addr}%s%s\n",
			      state->owner()->id(), target, wc ? " WC" : "",
			      rpt ? " RPT" : "");
	}

	upstream_path *path = new upstream_path(this, state, target, wc, rpt);
	if (path) {
		group_state &gst = n_gstates[state->owner()->id()];
		gst.joins.push_back(path);
		npaths++;
		if (npaths == 1) {
			n_jp_timer.start();
		}
	}

	return path;
}

void pim_neighbour::remove_path(upstream_path *path) {
	if (intf()->should_log(MESSAGE_SIG)) {
		log().xprintf("remove path %{Addr}%s%s\n", path->target(),
			      path->wc() ? " WC" : "", path->rpt() ? " RPT" : "");
	}

	std::map<inet6_addr, group_state>::iterator k =
		n_gstates.find(path->state()->owner()->id());
	if (k == n_gstates.end())
		return;

	upstream_jp_state::iterator i = std::find(k->second.joins.begin(),
						k->second.joins.end(), path);
	if (i == k->second.joins.end()) {
		i = std::find(k->second.prunes.begin(), k->second.prunes.end(), path);
		if (i == k->second.prunes.end())
			return;

		k->second.prunes.erase(i);
	} else {
		k->second.joins.erase(i);
	}

	npaths--;
	if (npaths == 0)
		n_jp_timer.stop();

	if (k->second.joins.empty() && k->second.prunes.empty()) {
		n_gstates.erase(k);
	}

	delete path;
}

static bool add_source_to_jp_message(int mtu, uint32_t &len, pim_encoded_source_address * &aptr,
		const in6_addr &addr, bool wc, bool rpt) {
	if ((int)(len + sizeof(pim_encoded_source_address)) > mtu)
		return false;
	aptr->construct(addr, wc, rpt);
	aptr = aptr->next();
	len += aptr->length();
	return true;
}

static bool build_block(int mtu, uint32_t &len, int &count, pim_encoded_source_address * &aptr,
			std::list<pim_neighbour::upstream_path *>::const_iterator &i,
			const std::list<pim_neighbour::upstream_path *>::const_iterator &e) {
	while (i != e) {
		if ((*i)->is_active()) {
			if (!(*i)->may_be_overridden()) {
				if (!add_source_to_jp_message(mtu, len, aptr,
					(*i)->target(), (*i)->wc(), (*i)->rpt()))
					return false;
				count++;
			} else if ((*i)->neigh()->intf()->should_log(INTERNAL_FLOW)) {
				pim_source_state_base *st = (*i)->state();

				(*i)->neigh()->log().xprintf(
					"Join/Prune for (%{addr}, %{Addr}%s) was suppressed.\n",
					st->addr(), st->owner()->id(),
					st->is_rpt() && !st->is_wildcard() ? ", RPT" : "");
			}
		}
		++i;
	}
	return true;
}

base_stream &pim_neighbour::log() const {
	return pim->log().xprintf("Neighbour(%s, %{addr}) ",
				  intf()->owner()->name(), n_addr.addr);
}

void pim_neighbour::handle_jp_timer() {
	pim_joinprune_message *msg;
	pim_joinprune_group *grp;
	uint32_t ngrps, len;

	msg = g_mrd->opktb->header<pim_joinprune_message>();
	grp = msg->groups();

	ngrps = 0;
	len = sizeof(pim_joinprune_message) + sizeof(pim_joinprune_group);

	uint32_t holdtime = n_intf->conf()->joinprune_holdtime() / 1000;

	pim_encoded_source_address *addr = grp->addrs();

	// int mtu = intf()->owner()->mtu();
	int mtu = 1280;

	for (upstream_state::const_iterator i = n_gstates.begin(); i != n_gstates.end(); i++) {
		if (!i->second.joins.empty() || !i->second.prunes.empty()) {

			int sjcount = 0;
			int spcount = 0;

			std::list<upstream_path *>::const_iterator a = i->second.joins.begin();
			std::list<upstream_path *>::const_iterator b = i->second.joins.end();

			while (!build_block(mtu, len, sjcount, addr, a, b)) {
				grp->construct(i->first, sjcount, 0);
				msg->construct(n_addr, ngrps + (sjcount ? 1 : 0), holdtime);
				n_intf->send_join_prune(msg);
				msg = g_mrd->opktb->header<pim_joinprune_message>();
				grp = msg->groups();
				addr = grp->addrs();
				sjcount = 0;
				ngrps = 0;
				len = sizeof(pim_joinprune_message) + sizeof(pim_joinprune_group);
			}

			a = i->second.prunes.begin();
			b = i->second.prunes.end();

			while (!build_block(mtu, len, spcount, addr, a, b)) {
				grp->construct(i->first, sjcount, spcount);
				msg->construct(n_addr, ngrps + ((sjcount || spcount) ? 1 : 0), holdtime);
				n_intf->send_join_prune(msg);
				msg = g_mrd->opktb->header<pim_joinprune_message>();
				grp = msg->groups();
				addr = grp->addrs();
				sjcount = 0;
				spcount = 0;
				ngrps = 0;
				len = sizeof(pim_joinprune_message) + sizeof(pim_joinprune_group);
			}


			if (sjcount || spcount) {
				grp->construct(i->first, sjcount, spcount);
				len += sizeof(pim_joinprune_group);

				grp = grp->next();
				addr = grp->addrs();
				ngrps++;
			}
		}
	}

	if (ngrps) {
		msg->construct(n_addr, ngrps, holdtime);

		n_intf->send_join_prune(msg);
	}
}

bool pim_neighbour::move_to_joins(upstream_path *path) {
	upstream_state::iterator k = n_gstates.find(path->state()->owner()->id());
	if (k == n_gstates.end())
		return false;

	upstream_jp_state::iterator i = std::find(k->second.prunes.begin(), k->second.prunes.end(), path);

	if (i == k->second.prunes.end()) {
		return false;
	}

	k->second.prunes.erase(i);
	k->second.joins.push_back(path);

	return true;
}

bool pim_neighbour::move_to_prunes(upstream_path *path) {
	upstream_state::iterator k = n_gstates.find(path->state()->owner()->id());
	if (k == n_gstates.end())
		return false;

	upstream_jp_state::iterator i = std::find(k->second.joins.begin(), k->second.joins.end(), path);

	if (i == k->second.joins.end()) {
		return false;
	}

	k->second.joins.erase(i);
	k->second.prunes.push_back(path);

	return true;
}

void pim_neighbour::output_info(base_stream &ctx, bool extended) const {
	ctx.write(localaddr()).write(", ");

	if (n_holdtimer.is_running())
		ctx.write(n_holdtimer.time_left_d());
	else
		ctx.write("n/a");

	ctx.newl();

	ctx.inc_level();

	if (has_dr_priority())
		ctx.xprintf("DR-Priority: %u\n", dr_priority());

	if (has_lan_delay()) {
		ctx.xprintf("LAN Propagation Delay: %ums Override Interval %ums\n",
			    propagation_delay(), override_interval());
	}

	if (!n_secaddrs.empty()) {
		ctx.writeline("Secondary-Addresses:");
		ctx.inc_level();
		for (std::set<in6_addr>::const_iterator k = n_secaddrs.begin();
						k != n_secaddrs.end(); k++)
			ctx.writeline(*k);
		ctx.dec_level();
	}

	if (extended) {
		ctx.writeline("Upstream J/P state:");
		ctx.inc_level();

		for (upstream_state::const_iterator i = n_gstates.begin();
						i != n_gstates.end(); i++) {
			ctx.writeline(i->first);
			ctx.inc_level();

			if (!i->second.joins.empty()) {
				ctx.writeline("Joins");
				ctx.inc_level();

				for (upstream_jp_state::const_iterator j =
						i->second.joins.begin();
						j != i->second.joins.end(); j++) {
					(*j)->output_info(ctx);
				}

				ctx.dec_level();
			}

			if (!i->second.prunes.empty()) {
				ctx.writeline("Prunes");
				ctx.inc_level();

				for (upstream_jp_state::const_iterator j =
						i->second.prunes.begin();
						j != i->second.prunes.end(); j++) {
					(*j)->output_info(ctx);
				}

				ctx.dec_level();
			}


			ctx.dec_level();
		}

		ctx.dec_level();
	}

	ctx.dec_level();
}

pim_neighbour::upstream_path::upstream_path(pim_neighbour *neigh,
				pim_source_state_base *state,
				const inet6_addr &targ, bool wc, bool rpt)
	: p_neigh(neigh), p_state(state), p_target(targ), p_wc(wc), p_rpt(rpt) {
	p_isjoin = true;
	p_active = false;
}

void pim_neighbour::upstream_path::remove(bool sendinvsingle) {
	if (sendinvsingle) {
		p_isjoin = !p_isjoin;
		send_single(true);
		p_isjoin = !p_isjoin;
	}

	p_neigh->remove_path(this);
}

void pim_neighbour::upstream_path::join(bool permanent) {
	p_isjoin = true;
	if (permanent) {
		if (p_neigh->move_to_joins(this) || !p_active) {
			send_single(false);
		}
	} else {
		if (p_neigh->move_to_joins(this) && p_active) {
			send_single(false);
		}
	}

	p_active = permanent;

	/* reset supression */
	p_last_seen = tval();
}

void pim_neighbour::upstream_path::prune(bool permanent) {
	p_isjoin = false;

	if (permanent) {
		if (p_neigh->move_to_prunes(this) || !p_active)
			send_single(false);
	} else {
		if (p_neigh->move_to_prunes(this) && p_active)
			send_single(false);
	}

	p_active = permanent;

	/* reset supression */
	p_last_seen = tval();
}

void pim_neighbour::upstream_path::send_single(bool now) const {
	if (!p_neigh->n_present)
		return;

	pim_joinprune_message *msg = g_mrd->opktb->header<pim_joinprune_message>();

	uint32_t holdtime = now ? 0 : (p_neigh->intf()->conf()->joinprune_holdtime() / 1000);
	msg->construct(p_neigh->n_addr, 1, holdtime);

	pim_joinprune_group *grp = msg->groups();
	grp->construct(p_state->owner()->id(), p_isjoin ? 1 : 0, p_isjoin ? 0 : 1);
	grp->addrs()->construct(p_target, p_wc, p_rpt);

	p_neigh->intf()->send_join_prune(msg);
}

void pim_neighbour::upstream_path::refresh_now() const {
	send_single(false);
}

void pim_neighbour::upstream_path::update_last_seen(uint32_t holdtime) {
	if (p_last_seen.secs() != 0 || p_last_seen.usecs() != 0) {
		uint32_t diff = (tval::now() - p_last_seen);

		/* still time to go and stored values give more
		 * supression, don't update vals. */
		if (diff < p_last_seen_holdtime
			&& ((p_last_seen_holdtime - diff) > holdtime)) {
			return;
		}
	}

	p_last_seen_holdtime = holdtime;
	p_last_seen.update_to_now();
}

bool pim_neighbour::upstream_path::may_be_overridden() const {
	if (p_last_seen.secs() == 0 && p_last_seen.usecs() == 0)
		return false;

	uint32_t t_joinsuppress =
		std::min(neigh()->intf()->suppressed_value(),
			p_last_seen_holdtime);

	/* diff holds the equivalent of Join Timer */
	uint32_t diff = (tval::now() - p_last_seen);

	return diff < t_joinsuppress;
}

void pim_neighbour::upstream_path::output_info(base_stream &ctx) const {
	ctx.xprintf("Target %{Addr}%s%s Owner: (%{addr}, %{Addr}%s)\n",
		    target(), wc() ? " WC" : "", rpt() ? " RPT" : "",
		    state()->addr(), state()->owner()->id(),
		    state()->is_rpt() && !state()->is_wildcard() ? ", RPT" : "");
}


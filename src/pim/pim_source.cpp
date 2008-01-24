/*
 * Multicast Routing Daemon (MRD)
 *   pim_source.cpp
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

#include <mrdpriv/pim/group.h>
#include <mrdpriv/pim/router.h>
#include <mrdpriv/pim/interface.h>
#include <mrdpriv/pim/def.h>

#include <mrd/mrd.h>

#include <cmath>

#include <string>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h>

/* from pim_oif.cpp */
extern const char *_oif_interest(pim_oif::interest);

pim_source_state_base::pim_source_state_base(pim_group_node *owner,
					const inet6_addr &address)
	: m_owner(owner), m_addr(address), m_upstream_path(0) {

	m_creation_time = tval::now();

	grab();
	m_previous_interest = true;
}

pim_source_state_base::~pim_source_state_base() {
	if (m_upstream_path) {
		m_upstream_path->remove();
		m_upstream_path = 0;
	}

	for (oifs::iterator i = m_oifs.begin(); i != m_oifs.end(); ++i) {
		delete *i;
	}

	m_oifs.clear();
}

bool pim_source_state_base::check_startup() {
	return true;
}

bool pim_source_state_base::set_oif(interface *intf, uint32_t timeout, bool join) {
	if (owner()->should_log(INTERNAL_FLOW)) {
		log().xprintf("set_oif %s %u %s\n", intf->name(), timeout,
			      join ? " join" : " prune");
	}

	pim_oif *selected = get_oif(intf);

	if (!selected) {
		/* Add the interface, to remove it next? No thank you. */
		if (!timeout)
			return true;

		selected = create_oif(intf);
		if (!selected)
			return false;
	}

	selected->update(join, timeout);

	return true;
}

bool pim_source_state_base::set_local_oif(interface *intf, bool join) {
	if (owner()->should_log(INTERNAL_FLOW)) {
		log().xprintf("set_local_oif %s %s\n", intf->name(),
			      join ? " join" : " prune");
	}

	pim_oif *selected = get_oif(intf);

	if (!selected) {
		selected = create_oif(intf);
		if (!selected)
			return false;
	}

	selected->change_local_membership(join ?
			pim_oif::Include : pim_oif::Exclude);

	return true;
}

bool pim_source_state_base::remove_oif(interface *intf) {
	for (oifs::iterator i = m_oifs.begin(); i != m_oifs.end(); ++i) {
		if ((*i)->intf() == intf) {
			pim_oif *oif = *i;
			m_oifs.erase(i);

			removing_oif(oif);

			delete oif;

			if (owner()->should_log(DEBUG))
				log().xprintf("Removed intf %s\n", intf->name());

			check_interest();

			return true;
		}
	}

	return false;
}

bool pim_source_state_base::release_oif(interface *intf, bool local) {
	for (oifs::iterator i = m_oifs.begin(); i != m_oifs.end(); ++i) {
		if ((*i)->intf() == intf) {
			if (local)
				(*i)->change_local_membership(pim_oif::NoInfo);
			else
				(*i)->update(true, 0);
			return true;
		}
	}

	return true;
}

pim_oif *pim_source_state_base::get_oif(interface *intf) const {
	for (oifs::const_iterator i = m_oifs.begin(); i != m_oifs.end(); ++i) {
		if ((*i)->intf() == intf) {
			return *i;
		}
	}

	return 0;
}

int pim_source_state_base::count_oifs() const {
	return m_oifs.size();
}

bool pim_source_state_base::join_desired() const {
	return get_downstream_interest() != pim_oif::NoInfo;
}

pim_oif::interest pim_source_state_base::get_downstream_interest() const {
	return get_oif_downstream_interest(false);
}

pim_oif::interest pim_source_state_base::get_oif_downstream_interest(bool checklocal) const {
	pim_oif::interest res = pim_oif::NoInfo;

	for (oifs::const_iterator i = m_oifs.begin();
			res != pim_oif::Include && i != m_oifs.end(); ++i) {
		pim_oif::interest k = (*i)->get_interest();

		if (k == pim_oif::Include) {
			res = pim_oif::Include;
		} else if (k == pim_oif::Exclude) {
			if (res != pim_oif::Include)
				res = pim_oif::Exclude;
		} else if (checklocal && k == pim_oif::NoInfo) {
			if ((*i)->get_real_local_interest() == pim_oif::Include)
				res = pim_oif::Include;
			else if ((*i)->get_real_local_interest() == pim_oif::Exclude
					&& res != pim_oif::Include)
				res = pim_oif::Exclude;
		}
	}

	return res;
}

const in6_addr &pim_source_state_base::join_target() const {
	return m_addr;
}

bool pim_source_state_base::check_interest() {
	bool current_interest = state_desired();

	if (current_interest != m_previous_interest) {
		m_previous_interest = current_interest;

		if (!current_interest) {
			int _prev_count = get_refcount();

			release();

			if (_prev_count == 1) {
				/* If the previous refcount was 1,
				 * we reached 0 after the release
				 * and the state was removed */
				return false;
			}
		} else {
			grab();
		}
	}

	return true;
}

bool pim_source_state_base::check_interest_and_update_upstream() {
	if (!check_interest())
		return false;

	update_upstream();

	return true;
}

void pim_source_state_base::dr_changed(pim_interface *intf, bool islocal) {
	for (oifs::iterator i = m_oifs.begin(); i != m_oifs.end(); ++i) {
		if ((*i)->intf() == intf->owner())
			(*i)->dr_changed(islocal);
	}
}

void pim_source_state_base::clear_interface_references(interface *intf) {
	if (get_oif(intf)) {
		remove_oif(intf);
	}
}

bool pim_source_state_base::state_desired() const {
	return join_desired();
}

void pim_source_state_base::check_upstream_path() {
}

void pim_source_state_base::build_upstream_state() {
	pim_neighbour *neigh = upstream_neighbour();

	if (!m_upstream_path || m_upstream_path->neigh() != neigh) {
		bool had = false;
		if (m_upstream_path) {
			m_upstream_path->remove();
			m_upstream_path = 0;
			had = true;

			if (owner()->should_log(DEBUG))
				log().writeline("Removing upstream path, "
					        "possibly changing.");
		}

		if (neigh) {
			update_upstream();
		} else if (am_self_upstream()) {
			if (had && owner()->should_log(DEBUG))
				log().writeline("I'm the upstream neighbour.");
		} else if (had) {
			if (owner()->should_log(DEBUG))
				log().writeline("Lost the upstream neighbour.");
		}

		upstream_changed();
	}
}

void pim_source_state_base::update_upstream() {
	if (join_desired()) {
		pim_neighbour *neigh = upstream_neighbour();

		if (!m_upstream_path && neigh) {
			m_upstream_path = neigh->add_path(this, join_target(),
					is_wildcard(), is_rpt());

			if (m_upstream_path && owner()->should_log(DEBUG)) {
				log().xprintf("Upstream neighbor is %{Addr} in"
					      " %s.\n", neigh->localaddr(),
					      neigh->intf()->owner()->name());
			}
		}
	} else if (m_upstream_path) {
		m_upstream_path->remove();
		m_upstream_path = 0;
	}

	if (m_upstream_path) {
		if (get_downstream_interest() == pim_oif::Include) {
			m_upstream_path->join(true);
		} else {
			m_upstream_path->prune(true);
		}
	}
}

void pim_source_state_base::wildcard_state_existance_changed(bool) {
	/* empty */
}

pim_oif *pim_source_state_base::create_oif(interface *intf) {
	if (!intf)
		return 0;

	pim_oif *oif = create_oif(this, intf);

	if (oif) {
		m_oifs.push_back(oif);

		if (owner()->should_log(DEBUG))
			log().xprintf("Added intf %s\n", intf->name());
	}

	return oif;
}

void pim_source_state_base::output_common_info(base_stream &ctx) const {
	ctx.inc_level();

	ctx.xprintf("Input Interface: %s, ", iif() ? iif()->name() : "(None)");

	pim_neighbour *neigh = upstream_neighbour();

	ctx.write("Upstream: ");
	if (is_source_local()) {
		ctx.write("(Local)");
	} else if (neigh) {
		ctx.write(neigh->localaddr());
		if (!m_upstream_path) {
			ctx.write(", No state");
		}
	} else if (am_self_upstream()) {
		ctx.write("(Self)");
	} else {
		ctx.write("(None)");
	}

	ctx.newl();

	if (!m_oifs.empty()) {
		ctx.writeline(is_wildcard() ?
			"Output Interfaces:" : "Immediate Output Interfaces:");

		ctx.inc_level();

		for (oifs::const_iterator i = m_oifs.begin(); i != m_oifs.end(); i++) {
			(*i)->output_info(ctx);
		}

		ctx.dec_level();
	}

	ctx.dec_level();
}

void pim_source_state_base::removing_oif(pim_oif *) {
	/* empty */
}

void pim_source_state_base::upstream_changed() {
	/* empty */
}

void pim_source_state_base::destructor() {
	owner()->remove_state(this);
}

pim_source_state_common::pim_source_state_common(pim_group_node *owner,
					const inet6_addr &addr)
	: pim_source_state_base(owner, addr), m_iif(0),
		m_neigh_watcher(this, std::mem_fun(&pim_source_state_common::neighbour_changed), this) {
}

bool pim_source_state_common::check_startup() {
	return m_neigh_watcher.check_startup();
}

pim_oif *pim_source_state_common::create_oif(pim_source_state_base *state, interface *intf) const {
	return new pim_common_oif(state, intf);
}

void pim_source_state_common::assert_wstate_actions1(pim_common_oif *oif) {
	/*
	 * A1: Send Assert(S,G)
         *     Set Assert Timer to (Assert_Time - Assert_Override_Interval)
         *     Store self as AssertWinner(S,G,I)
         *     Store spt_assert_metric(S,I) as AssertWinnerMetric(S,G,I)
	 *
	 * for (*,G) is the same, but instead of (S,G) is (*,G) and
	 *  rpt_assert_metric(*,G,I)
	 */

	if (!oif->pim_intf())
		return;

	oif->change_assert_state(pim_common_oif::WonAssert);

	send_assert(oif->pim_intf());

	oif->restart_assert_timer_minus_override();
	oif->store_assert_info(0, path_metric(), path_protocol());
}

void pim_source_state_common::assert_lstate_actions2(pim_common_oif *oif,
			pim_neighbour *winner, uint32_t metric, uint32_t pref) {
	/*
	 * A2: Store new assert winner as AssertWinner(*,G,I) and assert
         *     winner metric as AssertWinnerMetric(*,G,I).
         *     Set Assert Timer to Assert_Time
	 */

	if (!oif->pim_intf())
		return;

	oif->change_assert_state(pim_common_oif::LostAssert);

	oif->store_assert_info(winner, metric, pref);
	oif->restart_assert_timer();
}

interface *pim_source_state_common::iif() const {
	return m_iif;
}

uint32_t pim_source_state_common::path_metric() const {
	return m_neigh_watcher.prefix_metric();
}

uint32_t pim_source_state_common::path_protocol() const {
	return m_neigh_watcher.prefix_protocol();
}

pim_neighbour *pim_source_state_common::upstream_neighbour() const {
	/* respect Assert Winner precedence */

	pim_common_oif *oif = (pim_common_oif *)get_oif(iif());
	if (oif && oif->current_assert_state() == pim_common_oif::LostAssert) {
		return oif->assert_winner();
	}

	return m_neigh_watcher.neigh();
}

bool pim_source_state_common::am_self_upstream() const {
	return m_neigh_watcher.self_upstream();
}

const in6_addr &pim_source_state_common::target_destination() const {
	return join_destination();
}

const inet6_addr &pim_source_state_common::target_group() const {
	return owner()->id();
}

void pim_source_state_common::check_upstream_path() {
	if (is_rpt() && !owner()->has_rp()) {
		/* for (*,G) and (S,G,rpt) states, the direction (RP address)
		 * might be any, i.e. no RP address is configured. */
		m_neigh_watcher.release();
	} else {
		m_neigh_watcher.invalidate();
	}
}

bool pim_source_state_common::could_assert(interface *intf) const {
	/* default behaviour returns false, i.e. (S,G,rpt) states */

	return false;
}

bool pim_source_state_common::assert_tracking_desired(interface *intf) const {
	/* default behaviour is false, only (S,G) states implement this */

	return false;
}

static bool _check_assert(const pim_source_state_base *s, interface *intf,
		const inet6_addr &addr, bool rpt, uint32_t metric, uint32_t pref) {
	if (s->is_rpt() == rpt) {
		uint32_t own_pref = s->path_protocol();
		uint32_t own_metric = s->path_metric();

		if (own_pref == pref) {
			if (own_metric == metric) {
				return intf->primary_addr() < addr;
			} else {
				return own_metric < metric;
			}
		} else {
			return own_pref < pref;
		}
	} else {
		return rpt;
	}
}

bool pim_source_state_common::check_assert(interface *intf, const inet6_addr &addr,
				bool rpt, uint32_t metric, uint32_t pref) const {
	if (could_assert(intf)) {
		return _check_assert(this, intf, addr, rpt, metric, pref);
	} else if (owner()->has_wildcard() && owner()->wildcard()->could_assert(intf)) {
		return _check_assert(owner()->wildcard(), intf, addr, rpt, metric, pref);
	} else {
		return false;
	}
}

extern sockaddr_in6 pim_all_routers_addr;

void pim_source_state_common::send_assert(pim_interface *intf) {
	if (!intf)
		return;

	uint32_t own_pref = path_protocol();
	uint32_t own_metric = path_metric();

	pim_assert_message *msg = g_mrd->opktb->header<pim_assert_message>();
	msg->construct(m_owner->id(), join_target(), is_wildcard(), own_pref, own_metric);

	intf->send_assert(msg);
}

void pim_source_state_common::send_assert_cancel(pim_interface *intf) {
	if (!intf)
		return;

	pim_assert_message *msg = g_mrd->opktb->header<pim_assert_message>();
	msg->construct(m_owner->id(), join_target(), true, 0x7fffffff, 0xffffffff);

	intf->send_assert(msg);
}

void pim_source_state_common::found_new_neighbour(pim_neighbour *neigh) {
	m_neigh_watcher.recheck_neighbour();
}

void pim_source_state_common::neighbour_lost(pim_neighbour *neigh) {
	if (m_upstream_path && m_upstream_path->neigh() == neigh)
		m_neigh_watcher.recheck_neighbour();

	for (oifs::iterator i = m_oifs.begin(); i != m_oifs.end(); ++i) {
		pim_common_oif *k = (pim_common_oif *)(*i);

		if (k->assert_winner() == neigh) {
			/* -> NI state, [Actions A5] */
			k->change_assert_state(pim_common_oif::AssertNoInfo);
		}
	}
}

void pim_source_state_common::clear_interface_references(interface *intf) {
	auto_grab grab(this);

	pim_source_state_base::clear_interface_references(intf);

	if (m_iif == intf) {
		if (m_upstream_path) {
			m_upstream_path->remove(false);
			m_upstream_path = 0;
		}

		removing_iif(m_iif);
		m_iif = 0;

		check_upstream_path();
	}
}

void pim_source_state_common::neighbour_changed(pim_neighbour_watcher_base *) {
	pim_interface *iif = m_neigh_watcher.tentative_interface();

	/* safeguard this source state instance */
	auto_grab grab(this);

	if (!m_iif || !iif || iif->owner() != m_iif) {
		if (m_iif) {
			pim_oif *oif = get_oif(m_iif);

			removing_iif(m_iif);
			m_iif = 0;

			if (oif) {
				/* oif may not exist if it was removed */
				oif_changed_state(oif, oif->get_interest());
			}
		}

		if (iif == 0 && m_oifs.empty() && is_wildcard()) {
			if (owner()->owner()->someone_lost_interest())
				return;
		}

		changed_iif(iif ? iif->owner() : 0);
	}

	build_upstream_state();
}

void pim_source_state_common::changed_iif(interface *intf) {
	m_iif = intf;
}

void pim_source_state_common::removing_iif(interface *) {
	/* empty */
}

pim_group_source_state::pim_group_source_state(pim_group_node *grp, const inet6_addr &addr)
	: pim_source_state_common(grp, addr),
		m_register_supression_timer("pim register supression timer", this,
				std::mem_fun(&pim_group_source_state::send_probe)) {

	m_spt = grp->is_ssm();
	m_local = false;
	m_mfa_inst = 0;
	m_sent_probe = false;
	m_assert_state = noinfo;
	m_kat_enabled = false;
	m_inherited_oifs = 0;

	m_fw_counter = 0;

	m_downstream_activity = false;
}

pim_group_source_state::~pim_group_source_state() {
	if (spt()) {
		pim_group_source_rpt_state *rptstate = owner()->get_rpt_state(addr());
		if (rptstate)
			rptstate->set_local_interest(pim_oif::Include);
	}

	if (m_iif) {
		if (m_mfa_inst)
			m_mfa_inst->release_iif(m_iif);
		m_iif = 0;
	}

	if (m_mfa_inst) {
		m_owner->mfa()->release_source_state(m_mfa_inst);
		m_mfa_inst = 0;
	}
}

void pim_group_source_state::changed_iif(interface *intf) {
	if (!intf) {
		m_iif = 0;
		return;
	}

	pim_oif *oif = get_oif(intf);

	if (!oif && m_inherited_oifs)
		oif = owner()->wildcard()->get_oif(intf);

	if (oif)
		update_fib(oif->intf(), -1);

	m_local = intf->in_same_subnet(m_addr);

	if (m_local)
		restart_kat();

	m_iif = intf;

	m_mfa_inst->set_iif(intf);

	merge_inherited_oifs();
}

void pim_group_source_state::removing_iif(interface *intf) {
	m_mfa_inst->release_iif(intf);
}

bool pim_group_source_state::check_startup() {
	if (!pim_source_state_common::check_startup())
		return false;

	/* only create MFIB states for (S,G) states */
	m_mfa_inst = owner()->mfa()->create_source_state(addr(), this);
	if (!m_mfa_inst) {
		return false;
	}

	/* for RP register encapsulation */
	if (!owner()->is_ssm())
		m_mfa_inst->change_flags(mfa_group_source::f_any_incoming,
			mfa_group_source::copy_full_packet);

	return true;
}

void pim_group_source_state::output_name(base_stream &os) const {
	os.xprintf("(%{addr})", addr());
}

bool pim_group_source_state::output_info(base_stream &ctx) const {
	base_stream &os = ctx.xprintf("(%{addr})", addr());

	if (m_spt)
		os.write(", SPT");

	if (m_kat_enabled) {
		int32_t diff = tval::now() - m_kat_last_update;

		if (diff <= 10000)
			os.write(", Active");
		else
			os.xprintf(", Inactive for %{duration}",
				   time_duration(diff));
	}

	os.xprintf(", Uptime: %{duration}\n", time_duration(uptime()));

	ctx.inc_level();

	if (m_register_supression_timer.is_running()) {
		ctx.xprintf("Register-Stop%s: %{duration}\n",
			    m_sent_probe ? ", pending" : "",
			    m_register_supression_timer.time_left_d());
	}

	ctx.dec_level();

	output_common_info(ctx);

	if (m_inherited_oifs && !m_inherited_oifs->empty()) {
		ctx.inc_level();

		int count = 0;
		for (oifs::const_iterator i = m_inherited_oifs->begin();
					i != m_inherited_oifs->end(); i++) {
			if (inherited_includes(*i))
				count++;
		}

		if (count) {
			ctx.writeline("Inherited Output Interfaces:");

			ctx.inc_level();

			for (oifs::const_iterator i = m_inherited_oifs->begin();
					i != m_inherited_oifs->end(); ++i) {
				if (inherited_includes(*i))
					(*i)->output_info(ctx);
			}

			ctx.dec_level();
		}

		ctx.dec_level();
	}

	return true;
}

pim_oif::interest pim_group_source_state::get_inherited_oif_downstream_interest() const {
	pim_oif::interest res = pim_oif::NoInfo;

	if (m_inherited_oifs) {
		for (oifs::const_iterator i = m_inherited_oifs->begin();
					i != m_inherited_oifs->end(); ++i) {
			if (inherited_includes(*i)) {
				pim_oif::interest k = (*i)->get_interest();

				if (k == pim_oif::Include)
					res = pim_oif::Include;
				else if (k == pim_oif::Exclude && res != pim_oif::Include)
					res = pim_oif::Exclude;
				else if (k == pim_oif::NoInfo) {
					if ((*i)->get_real_local_interest() == pim_oif::Include)
						res = pim_oif::Include;
					else if ((*i)->get_real_local_interest() == pim_oif::Exclude
							&& res != pim_oif::Include)
						res = pim_oif::Exclude;
				}
			}
		}
	}

	return res;
}

bool pim_group_source_state::state_desired() const {
	/* XXX non-SPT states which time-out are never removed */

	/* Don't remove if the state is active and (*,G) includes it */
	if (owner()->has_wildcard() && (!spt() || m_kat_enabled)) {
		if (owner()->wildcard()->get_oif_downstream_interest(true) != pim_oif::NoInfo)
			return true;
	}

	/* Don't remove this state if there is downstream interest in (S,G,rpt) */
	pim_group_source_rpt_state *rpt = owner()->get_rpt_state(addr());
	if (rpt) {
		if (rpt->get_oif_downstream_interest(true) != pim_oif::NoInfo)
			return true;
	}

	/* If the source is local keep it around while KAT is running */
	if (is_source_local() && m_kat_enabled)
		return true;

	return !m_oifs.empty();
}

bool pim_group_source_state::join_desired() const {
	/* If we have inherited interest */
	if (get_inherited_oif_downstream_interest() != pim_oif::NoInfo)
		return true;
	/* Or if we have immediate interest */
	if (get_oif_downstream_interest(false) != pim_oif::NoInfo)
		return true;

	return false;
}

bool pim_group_source_state::inherited_includes(pim_oif *oif) const {
	/* If it is an ImmediateOif, isn't proper */
	if (get_oif(oif->intf()))
		return false;

	pim_group_source_rpt_state *rptstate = owner()->get_rpt_state(addr());

	/* If there is a (S,G,rpt) ...
	 * ... Even if (S,G,rpt) is in Exclude, if (*,G) is include,
	 * the interface is in the inherited oifs */
	if (rptstate && oif->get_local_interest() != pim_oif::Include) {
		pim_oif *rptoif = rptstate->get_oif(oif->intf());

		/* If the InheritedOif is prunned in the (S,G,rpt), not proper */
		if (rptoif && rptoif->get_interest() == pim_oif::Exclude)
			return false;
	}

	return ((pim_common_oif *)oif)->current_assert_state() != pim_common_oif::LostAssert;
}

void pim_group_source_state::inherited_oif_changed_state(pim_oif *oif,
							 pim_oif::interest prev) {
	pim_oif::interest currint = oif->get_interest();

	if (owner()->should_log(INTERNAL_FLOW)) {
		log().xprintf("inherited_Intf(%s) changed state %s -> %s\n",
			      oif->intf()->name(), _oif_interest(prev),
			      _oif_interest(currint));
	}

	/* if the interface is no longer included in the inherited list
	 * and not in the immediate list, remove it */
	if (!inherited_includes(oif) && !get_oif(oif->intf())) {
		update_fib(oif->intf(), -1);

		if (owner()->should_log(INTERNAL_FLOW)) {
			log().xprintf("inherited_Intf(%s) rejected, not "
				      "proper.\n", oif->intf()->name());
		}

		return;
	}

	if (currint == pim_oif::Include) {
		update_fib(oif->intf(), 1);
	} else /* { pim_oif::Exclude, pim_oif::NoInfo } */ {
		update_fib(oif->intf(), -1);
	}

	check_interest_and_update_upstream();
}

void pim_group_source_state::update_fib(interface *intf, int change) {
	if (owner()->should_log(INTERNAL_FLOW)) {
		log().xprintf("update_fib(%s) += %i [with iif=%s]\n",
			      intf->name(), change, iif() ? iif()->name() : 0);
	}

	if (change == 0 || intf == iif())
		return;

	if (change == -1)
		m_mfa_inst->release_oif(intf);
	else if (change == 1)
		m_mfa_inst->add_oif(intf);
}

static bool _check_oiflist_interest(const pim_source_state_base::oifs &olist) {
	for (pim_source_state_base::oifs::const_iterator i = olist.begin();
				i != olist.end(); ++i) {
		if ((*i)->get_interest() == pim_oif::Include)
			return true;
	}

	return false;
}

void pim_group_source_state::check_downstream_activity() {
	bool newval = _check_oiflist_interest(m_oifs);

	if (!newval && m_inherited_oifs) {
		newval = _check_oiflist_interest(*m_inherited_oifs);
	}

	if (newval != m_downstream_activity) {
		m_downstream_activity = newval;

		if (owner()->should_log(INTERNAL_FLOW))
			log().xprintf("Internal activity changed to %b\n",
				      m_downstream_activity);

		if (m_downstream_activity) {
			/* was false */
			if (g_mrd->interest_in_active_states())
				g_mrd->state_is_active(owner()->owner(), addr(), true);
		} else {
			/* is false */
			if (g_mrd->interest_in_active_states())
				g_mrd->state_is_active(owner()->owner(), addr(), false);
		}
	}
}

const in6_addr &pim_group_source_state::join_destination() const {
	return addr();
}

pim_oif::interest pim_group_source_state::get_downstream_interest() const {
	if (m_inherited_oifs) {
		for (oifs::const_iterator i = m_inherited_oifs->begin();
				i != m_inherited_oifs->end(); ++i) {
			if (inherited_includes(*i) &&
				(*i)->get_interest() == pim_oif::Include)
				return pim_oif::Include;
		}
	}

	return pim_source_state_base::get_downstream_interest();
}

void pim_group_source_state::removing_oif(pim_oif *oif) {
	update_fib(oif->intf(), -1);

	check_downstream_activity();

	/* -> NI state, [Actions A4] */

	if (((pim_common_oif *)oif)->current_assert_state() == pim_common_oif::WonAssert) {
		send_assert_cancel(oif->pim_intf());
	}
}

void pim_group_source_state::upstream_changed() {
	/* Whenever the upstream for (*,G) or (S,G) changes,
	 * notify the (S,G,rpt) state as join_desired() may change */

	pim_group_source_rpt_state *rptstate = owner()->get_rpt_state(addr());

	if (rptstate) {
		rptstate->update_upstream();
	}
}

void pim_group_source_state::update_fw_counters() {
	uint64_t bytes;

	m_mfa_inst->get_input_counter(bytes);

	if (m_fw_counter != bytes) {
		restart_kat();
	}

	m_fw_counter = bytes;
}

void pim_group_source_state::set_spt(bool b) {
	if (m_spt == b)
		return;

	if (b)
		restart_kat();

	if (owner()->should_log(DEBUG))
		log().xprintf("%sin Source Path Tree (SPT).\n",
			      !b ? "not " : "");

	m_spt = b;

	update_upstream();

	update_rpts();
}

bool pim_group_source_state::has_downstream_interest(bool includelocal) const {
	for (oifs::const_iterator i = m_oifs.begin(); i != m_oifs.end(); ++i) {
		if ((*i)->get_interest(includelocal) == pim_oif::Include)
			return true;
	}

	return false;
}

void pim_group_source_state::rp_changed() {
	update_rpts();

	/* XXX also do this when register_supression is running */
	m_mfa_inst->change_flags(mfa_group_source::f_any_incoming,
		owner()->has_rp() ? mfa_group_source::copy_full_packet : mfa_group_source::no_action);
}

bool pim_group_source_state::could_assert(interface *intf) const {
	/* SPTbit(S,G)==TRUE AND RPF_interface(S) != I */
	if (!spt() || !iif() || intf == iif())
		return false;
	/* I in [joins(*,*,RP(G)) + joins(*,G) - prunes(S,G,rpt)]
	 *       + [ pim_include(*,G) - pim_exclude(S,G) ]
	 *       - lost_assert(*,G)
	 *       + joins(S,G) + pim_include(S,G)
	 *
	 * They complicate so much..
	 *
	 * This is, if I is in InheritedOifs or ImmediateOifs and
	 * not in lost_assert(*,G) */

	if (m_inherited_oifs) {
		for (oifs::const_iterator i = m_inherited_oifs->begin();
				i != m_inherited_oifs->end(); ++i) {
			if ((*i)->intf() == intf) {
				if (inherited_includes(*i)) {
					if ((*i)->get_interest() == pim_oif::Include)
						return true;
				}

				break;
			}
		}
	}

	pim_oif *oif = get_oif(intf);

	if (oif) {
		return oif->get_interest() == pim_oif::Include;
	}

	return false;
}

bool pim_group_source_state::assert_tracking_desired(interface *intf) const {
	if (m_inherited_oifs) {
		for (oifs::const_iterator i = m_inherited_oifs->begin();
				i != m_inherited_oifs->end(); ++i) {
			if (intf == (*i)->intf()) {
				if (inherited_includes(*i)) {
					if ((*i)->get_interest() == pim_oif::Include)
						return true;
				}
			}
		}
	}

	pim_oif *oif = get_oif(intf);

	if (oif) {
		if (oif->get_interest() == pim_oif::Include
			&& oif->get_local_interest() == pim_oif::NoInfo) {
			return true;
		}

		if (oif->get_local_interest() == pim_oif::Include) {
			if (((pim_common_oif *)oif)->current_assert_state() == pim_common_oif::WonAssert)
				return true;

			pim_interface *pimintf = pim->get_interface(intf);
			if (pimintf && pimintf->am_dr())
				return true;
		}
	}

	if (iif() == intf && join_desired())
		return true;

	if (!spt() && owner()->has_wildcard()
		&& owner()->wildcard()->iif() == intf && owner()->wildcard()->join_desired())
		return true;

	return false;
}

void pim_group_source_state::handle_assert(interface *intf, const in6_addr &from,
					   bool rpt, uint32_t metric, uint32_t pref) {
	/* (S,G) Assert state machine */
	pim_common_oif *oif = (pim_common_oif *)get_oif(intf);
	if (!oif) {
		return;
	}

	/* we can be sure it exists */
	pim_interface *pintf = pim->get_interface(intf);

	pim_neighbour *neigh = pintf->get_neighbour(from);

	if (oif->current_assert_state() == pim_common_oif::AssertNoInfo) {
		if (could_assert(intf) && (rpt || check_assert(intf, from, rpt, metric, pref))) {
			/* -> W state, [Actions A1] */
			assert_wstate_actions1(oif);
		} else if (!rpt && assert_tracking_desired(intf)) {
			/* -> L state, [Actions A6]
			 *
			 * [Actions A6] is [Actions A2] plus SPTBit(S,G) = TRUE */

			assert_lstate_actions2(oif, neigh, metric, pref);

			if (intf == iif() && m_upstream_path)
				set_spt(true);
		}
	} else if (oif->current_assert_state() == pim_common_oif::WonAssert) {
		if (check_assert(intf, from, rpt, metric, pref)) {
			/* [Actions A3] */

			send_assert(pintf);
			oif->restart_assert_timer_minus_override();
		} else {
			/* L state, [Actions A2] */
			assert_lstate_actions2(oif, neigh, metric, pref);
		}
	} else if (oif->current_assert_state() == pim_common_oif::LostAssert) {
		if (!check_assert(intf, from, rpt, metric, pref)) {
			/* L state, [Actions A2] */
			assert_lstate_actions2(oif, neigh, metric, pref);
		} else if (neigh == oif->assert_winner()) {
			oif->change_assert_state(pim_common_oif::AssertNoInfo);
		}
	}
}

void pim_group_source_state::update_rpts() const {
	pim_group_source_rpt_state *rptstate;

	/*
	 * (S,G,rpt) creation follows these rules:
	 *
	 *  - S must not be local
	 *  - (*,G) must exist (i.e. we only want to prune the RPT tree if it exists)
	 *  - SPTbit for S must be TRUE
	 */

	if (!is_source_local() && owner()->has_wildcard() && spt()) {
		/* Merge the interfaces into the RPT state, but in reversed interest */
		rptstate = (pim_group_source_rpt_state *)owner()->create_state(addr(), true);

		if (rptstate)
			rptstate->set_local_interest(pim_oif::Exclude);
	} else {
		rptstate = owner()->get_rpt_state(addr());

		if (rptstate)
			rptstate->set_local_interest(pim_oif::Include);
	}
}

void pim_group_source_state::merge_inherited_oifs() {
	if (m_iif && m_inherited_oifs) {
		for (oifs::const_iterator i = m_inherited_oifs->begin();
				i != m_inherited_oifs->end(); ++i) {
			inherited_oif_changed_state(*i, pim_oif::NoInfo);
		}
	}
}

void pim_group_source_state::wildcard_state_existance_changed(bool created) {
	if (created) {
		update_upstream();

		m_inherited_oifs = owner()->wildcard()->get_oifs();

		merge_inherited_oifs();

		update_rpts();
	} else if (m_inherited_oifs) {
		/* If wildcard state was removed, RPT state is already gone
		 * so we don't need to update_rpts again */

		/* release any used inherited oif from the MFIB (S,G) state */
		for (oifs::const_iterator i = m_inherited_oifs->begin();
				i != m_inherited_oifs->end(); ++i) {
			interface *intf = (*i)->intf();

			if (!get_oif(intf))
				update_fib(intf, -1);
		}

		m_inherited_oifs = 0;
	}

	check_downstream_activity();
}

void pim_group_source_state::forward_to_rp(interface *iif, ip6_hdr *hdr, uint16_t len) {
	if (m_owner->is_ssm() || m_owner->is_self_rp()
		|| m_register_supression_timer.is_running())
		return;

	pim_interface *pi = pim->get_interface(iif);

	/* if PIM is disabled in this interface or we aren't the DR for Iif, dont register */
	if (!pi || !pi->am_dr())
		return;

	m_owner->forward_to_rp(this, iif, hdr, len);
}

void pim_group_source_state::register_stop() {
	if (m_iif) {
		if (!m_register_supression_timer.is_running()
		    && owner()->should_log(EXTRADEBUG)) {
			log().writeline("Stopped sending Register messages to RP");
		}

		pim_intfconf_node *conf = (pim_intfconf_node *)m_iif->conf()->get_child("pim");

		uint32_t regsupr = conf->register_supression_timeout();
		uint32_t val = regsupr / 2 + ((mrd::get_randu32() % 100) * regsupr) / 100;

		uint32_t probe = conf->probe_time();

		if (val < probe)
			val = probe * 2;

		val -= probe;

		m_register_supression_timer.start_or_update(val, false);

		m_sent_probe = false;
	}
}

void pim_group_source_state::send_probe() {
	if (m_owner->is_ssm() || !m_owner->has_rp_path()) {
		return;
	}

	if (m_sent_probe)
		return;

	struct {
		ip6_hdr ip6hdr;
		pim_message pimhdr;
	} dummy;

	memset(&dummy, 0, sizeof(dummy));

	dummy.ip6hdr.ip6_vfc = 0x60;
	dummy.ip6hdr.ip6_src = m_addr;
	dummy.ip6hdr.ip6_dst = m_owner->id();
	dummy.ip6hdr.ip6_plen = 4;
	dummy.ip6hdr.ip6_nxt = IPPROTO_PIM;
	dummy.ip6hdr.ip6_hops = 255;

	dummy.pimhdr.vt = 0;
	dummy.pimhdr.build_checksum(m_addr, m_owner->id(), sizeof(pim_message));

	pim_register_message *msg = g_mrd->opktb->header<pim_register_message>();
	memset(msg, 0, sizeof(*msg));

	memcpy(msg->ip6_header(), &dummy, sizeof(dummy));

	msg->construct(false, true);

	pim->send_register_probe(m_owner->pref_source_towards_rp(),
				 m_owner->rpaddr(), msg, sizeof(dummy));

	m_sent_probe = true;

	m_register_supression_timer.start_or_update(
		m_iif->conf()->get_child_property("pim", "probe-time")->get_unsigned(), false);
}

void pim_group_source_state::trigger_register_stop(const in6_addr *from) {
	node *_conf = m_iif ?
		m_iif->conf() : g_mrd->default_interface_configuration();

	pim_intfconf_node *conf = (pim_intfconf_node *)_conf->get_child("pim");

	/* assert(conf); */

	uint32_t rslim = conf->register_stop_rate_limit();
	uint32_t rslen = conf->register_stop_rate_timelen();

	bool send = false;

	if (rslim > 0) {
		std::map<in6_addr, register_stop_state>::iterator j = m_register_stop_router_rates.find(*from);
		if (j == m_register_stop_router_rates.end()) {
			send = true;
			m_register_stop_router_rates[*from].count = 0;
			m_register_stop_router_rates[*from].last = tval::now().round_milisecs();
		} else {
			j->second.count++;
			if (j->second.count >= rslim) {
				j->second.count = 0;
				send = true;
			}
			tval now = tval::now();
			if ((now.round_milisecs() - j->second.last) >= (((uint64_t)rslen) * 1000)) {
				j->second.last = now.round_milisecs();
				send = true;
			}
		}
	} else {
		send = true;
	}

	if (send)
		send_register_stop_to_router(from);
}

void pim_group_source_state::send_register_stop_to_router(const in6_addr *addr) const {
	owner()->send_register_stop_to_router(m_addr, *addr);
}

void pim_group_source_state::forward(interface *intf, ip6_hdr *hdr, uint16_t len) {
	g_mrd->mfa()->forward(intf, hdr, len);
}

void pim_group_source_state::trigger_assert(interface *intf) {
	pim_common_oif *oif = (pim_common_oif *)get_oif(intf);
	if (!oif)
		return;

	if (oif->current_assert_state() == pim_common_oif::LostAssert)
		return;

	/* -> W state, [Actions A1] */
	assert_wstate_actions1(oif);
}

bool pim_group_source_state::lost_assert_rpt(pim_common_oif *oif) const {
	if (!owner()->has_wildcard()) {
		/* No RPT */
		return false;
	}

	if ((oif->intf() == iif() && spt())
		|| oif->intf() == owner()->wildcard()->iif())
		return false;

	if (!oif) {
		/* Same as Assert NoInfo */
		return false;
	}

	return oif->current_assert_state() == pim_common_oif::LostAssert;
}

void pim_group_source_state::oif_changed_state(pim_oif *_oif, pim_oif::interest prev) {
	pim_common_oif *oif = (pim_common_oif *)_oif;

	/* safeguard this source state instance, remove_oif may
	 * trigger removal */
	auto_grab grab(this);

	if (!oif->has_interest()) {
		remove_oif(oif->intf());
	} else {
		if (oif->get_interest() == pim_oif::Include)
			update_fib(oif->intf(), 1);
		else /* Exclude, NoInfo */ {
			update_fib(oif->intf(), -1);
		}

		/* If im Assert Winner -> NI Info, [Actions A4] */
		if (oif->current_assert_state() == pim_common_oif::WonAssert
			&& !could_assert(oif->intf())) {

			oif->change_assert_state(pim_common_oif::AssertNoInfo, false);

			send_assert_cancel(oif->pim_intf());
		}
	}

	check_downstream_activity();

	check_interest_and_update_upstream();
}

pim_group_source_rpt_state::pim_group_source_rpt_state(pim_group_node *owner, const inet6_addr &addr)
	: pim_source_state_base(owner, addr) {
	m_local_interest = pim_oif::Include;
}

pim_oif *pim_group_source_rpt_state::create_oif(pim_source_state_base *state, interface *intf) const {
	return new pim_sg_rpt_oif(state, intf);
}

interface *pim_group_source_rpt_state::iif() const {
	return owner()->wildcard()->iif();
}

uint32_t pim_group_source_rpt_state::path_metric() const {
	return owner()->wildcard()->path_metric();
}

uint32_t pim_group_source_rpt_state::path_protocol() const {
	return owner()->wildcard()->path_protocol();
}

pim_neighbour *pim_group_source_rpt_state::upstream_neighbour() const {
	/* if I_Am_Assert_Loser(S, G, RPF_interface(RP(G)))
	 *   return AssertWinner(S, G, RPF_interface(RP(G))) */

	pim_group_source_state *state = owner()->get_state(addr());

	if (state) {
		pim_common_oif *oif = (pim_common_oif *)state->get_oif(iif());
		if (oif && oif->current_assert_state() == pim_common_oif::LostAssert) {
			return oif->assert_winner();
		}
	}

	/* else return RPF'(*,G) */
	return owner()->wildcard()->upstream_neighbour();
}

bool pim_group_source_rpt_state::am_self_upstream() const {
	return owner()->wildcard()->am_self_upstream();
}

pim_oif::interest pim_group_source_rpt_state::get_downstream_interest() const {
	if (m_local_interest == pim_oif::Exclude)
		return pim_oif::Exclude;
	return pim_source_state_base::get_downstream_interest();
}

void pim_group_source_rpt_state::set_local_interest(pim_oif::interest oifint) {
	if (oifint != m_local_interest) {
		m_local_interest = oifint;

		check_interest_and_update_upstream();
	}
}

bool pim_group_source_rpt_state::join_desired() const {
	/*
	 *  - Upstream neigh for RPT MUST be different than Upstream neigh for
	 *  S or else we don't really need to explicitly prune (S,G,rpt), our
	 *  upstream will do that for us
	 */

	pim_group_source_state *src = owner()->get_state(addr());
	if (src) {
		/* PruneDesired if RPF'(*,G) != RPF'(S,G) */
		if (upstream_neighbour()
			&& src->upstream_neighbour() == upstream_neighbour())
			return false;
	}

	return m_local_interest == pim_oif::Exclude
		|| pim_source_state_base::join_desired();
}

bool pim_group_source_rpt_state::state_desired() const {
	return m_local_interest == pim_oif::Exclude
		|| pim_source_state_base::state_desired();
}

void pim_group_source_rpt_state::rp_changed() {
	check_upstream_path();
}

bool pim_group_source_rpt_state::output_info(base_stream &ctx) const {
	ctx.xprintf("(%{addr}, RPT) Uptime: %{duration}\n", addr(),
		    time_duration(uptime()));

	output_common_info(ctx);

	ctx.inc_level();

	ctx.xprintf("Local interest: %s\n",
		    m_local_interest == pim_oif::Include ?
			"Include" : "Exclude");

	ctx.dec_level();

	return true;
}

void pim_group_source_rpt_state::oif_changed_state(pim_oif *oif,
						   pim_oif::interest prev) {
	pim_oif::interest currint = oif->get_interest();

	/* safeguard this source state instance, remove_oif
	 * may trigger removal */
	grab();

	if (currint != pim_oif::Exclude) {
		if (!oif->has_interest() || currint == pim_oif::Include)
			remove_oif(oif->intf());
	}

	/* get non-RPT state before check_interest as we may be removed */
	pim_group_source_state *state = owner()->get_state(addr());
	pim_oif *rptoif = state ? owner()->wildcard()->get_oif(oif->intf()) : 0;

	check_interest_and_update_upstream();

	release();

	/* even if we were removed we are safe as this stuff is in the stack */
	if (rptoif)
		state->inherited_oif_changed_state(rptoif, prev);
}

void pim_group_source_rpt_state::wildcard_state_existance_changed(bool created) {
	if (!created)
		owner()->remove_state(this);
}

void pim_group_source_rpt_state::output_name(base_stream &os) const {
	os.xprintf("(%{addr}, RPT)", addr());
}

pim_group_wildcard_state::pim_group_wildcard_state(pim_group_node *parent)
	: pim_source_state_common(parent, inet6_addr::any()) {}

pim_group_wildcard_state::~pim_group_wildcard_state() {
}

void pim_group_wildcard_state::output_name(base_stream &os) const {
	os.write("(*)");
}

void pim_group_wildcard_state::build_upstream_state() {
	pim_source_state_base::build_upstream_state();

	owner()->rpt_upstream_changed();
}

void pim_group_wildcard_state::rp_changed() {
	check_upstream_path();
}

bool pim_group_wildcard_state::could_assert(interface *intf) const {
	if (!iif() || intf == iif())
		return false;

	pim_oif *oif = get_oif(intf);

	if (oif) {
		return oif->get_interest() == pim_oif::Include;
	}

	return false;
}

void pim_group_wildcard_state::handle_assert(interface *intf, const in6_addr &from,
					bool rpt, uint32_t metric, uint32_t pref) {
	/* (*,G) Assert state machine */
	pim_common_oif *oif = (pim_common_oif *)get_oif(intf);
	if (!oif) {
		return;
	}

	/* we can be sure it exists */
	pim_interface *pintf = pim->get_interface(intf);

	pim_neighbour *neigh = pintf->get_neighbour(from);

	if (oif->current_assert_state() == pim_common_oif::AssertNoInfo) {
		if (could_assert(intf) && rpt && check_assert(intf, from, rpt, metric, pref)) {
			/* -> W state, [Actions A1] */
			assert_wstate_actions1(oif);
		} else if (rpt && assert_tracking_desired(intf)) {
			/* -> L state, [Actions A2] */
			assert_lstate_actions2(oif, neigh, metric, pref);
		}
	} else if (oif->current_assert_state() == pim_common_oif::WonAssert) {
		if (check_assert(intf, from, rpt, metric, pref)) {
			/* [Actions A3] */

			send_assert(pintf);
			oif->restart_assert_timer_minus_override();
		} else {
			/* L state, [Actions A2] */
			assert_lstate_actions2(oif, neigh, metric, pref);
		}
	} else if (oif->current_assert_state() == pim_common_oif::LostAssert) {
		if (!check_assert(intf, from, rpt, metric, pref)) {
			/* L state, [Actions A2] */
			assert_lstate_actions2(oif, neigh, metric, pref);
		} else if (neigh == oif->assert_winner()) {
			oif->change_assert_state(pim_common_oif::AssertNoInfo);
		}
	}
}

const in6_addr &pim_group_wildcard_state::join_target() const {
	return owner()->rpaddr();
}

const in6_addr &pim_group_wildcard_state::join_destination() const {
	return owner()->rpaddr();
}

bool pim_group_wildcard_state::output_info(base_stream &ctx) const {
	ctx.xprintf("(*) Uptime: %{duration}\n", time_duration(uptime()));

	output_common_info(ctx);

	return true;
}

void pim_group_wildcard_state::oif_changed_state(pim_oif *_oif, pim_oif::interest prevint) {
	pim_common_oif *oif = (pim_common_oif *)_oif;

	auto_grab grab(this);

	/* this must be called before as the remove_oif will remove oif */
	owner()->inherited_oif_changed_state(oif, prevint);

	if (!oif->has_interest()) {
		remove_oif(oif->intf());
	} else if (oif->get_interest() != pim_oif::Include) {
		/* If im Assert Winner -> NI state, [Actions A4] */

		if (oif->current_assert_state() == pim_common_oif::WonAssert
			&& !could_assert(oif->intf())) {
			oif->change_assert_state(pim_common_oif::AssertNoInfo, false);

			send_assert_cancel(oif->pim_intf());
		}
	}

	check_interest_and_update_upstream();
}

bool pim_group_wildcard_state::state_desired() const {
	return !m_oifs.empty();
}

void pim_group_wildcard_state::removing_oif(pim_oif *oif) {
	owner()->inherited_oif_changed_state(oif, pim_oif::Include);
}

void pim_group_wildcard_state::upstream_changed() {
	/* Whenever the upstream for (*,G) or (S,G) changes,
	 * notify the (S,G,rpt) state as join_desired() may change */

	owner()->rpt_update_upstream();
}

base_stream &pim_source_state_base::log() const {
	base_stream &os = owner()->log();
	output_name(os);
	return os.write(" ");
}


/*
 * Multicast Routing Daemon (MRD)
 *   pim_oif.cpp
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

const char *_oif_interest(pim_oif::interest i) {
	switch (i) {
	case pim_oif::NoInfo:
		return "NoInfo";
	case pim_oif::Include:
		return "Include";
	case pim_oif::Exclude:
		return "Exclude";
	}
	return 0;
}

pim_oif::pim_oif(pim_source_state_base *state, interface *intf)
	: m_state(state), m_intf(intf),
	m_timer("", this, std::mem_fun(&pim_oif::timed_out)),
	m_pp_timer("", this, std::mem_fun(&pim_oif::pp_timed_out)) {

	m_timer.name = "pim_oif ";
	m_timer.name += intf->name();
	m_pp_timer.name = "pim oif prune pending ";
	m_pp_timer.name += intf->name();

	m_local = NoInfo;
	m_jpstate = JPNoInfo;
}

pim_oif::~pim_oif() {
}

pim_interface *pim_oif::pim_intf() const {
	return pim->get_interface(m_intf);
}

void pim_oif::change_local_membership(interest l) {
	interest prev = get_interest();

	m_local = l;

	changed_state(prev);
}

static const char *_state_name(pim_oif::state st) {
	if (st == pim_oif::JPNoInfo) {
		return "NoInfo";
	} else if (st == pim_oif::Joined) {
		return "Joined";
	} else if (st == pim_oif::PendingPrune) {
		return "PendingPrune";
	} else if (st == pim_oif::Pruned) {
		return "Pruned";
	} else {
		return "Unknown";
	}
}

bool pim_oif::change_state(state ns) {
	if (ns == m_jpstate)
		return false;

	interest prev = get_interest();

	if (m_state->owner()->should_log(EXTRADEBUG)) {
		log().xprintf("changed J/P State %s -> %s\n",
			      _state_name(m_jpstate), _state_name(ns));
	}

	m_jpstate = ns;

	if (m_jpstate == JPNoInfo) {
		m_timer.stop();
		m_pp_timer.stop();
	}

	changed_state(prev);

	return true;
}

void pim_oif::changed_state(interest prev) {
	if (prev == get_interest())
		return;

	if (m_state->owner()->should_log(EXTRADEBUG)) {
		log().xprintf("Changed state %s -> %s\n",
			      _oif_interest(prev),
			      _oif_interest(get_interest()));
	}

	m_state->oif_changed_state(this, prev);
}

bool pim_oif::needs_supressing() const {
	pim_interface *intf = pim->get_interface(m_state->iif());

	if (intf)
		return intf->get_neighbours().size() > 1;

	return false;
}

uint32_t pim_oif::jp_override_interval() const {
	if (!needs_supressing())
		return 0;

	pim_interface *intf = pim_intf();
	if (!intf)
		return 0;

	return intf->effective_propagation_delay()
		+ intf->effective_override_interval();
}

base_stream &pim_oif::log() const {
	return m_state->log().xprintf("Intf(%s) ", m_intf->name());
}

void pim_oif::update(bool join, uint32_t hold) {
	if ((join && m_jpstate != Joined)
			|| (!join && m_jpstate != Pruned)) {
		if (m_state->owner()->should_log(EXTRADEBUG)) {
			log().xprintf("Updated with %s for %{duration}\n",
				      join ? "join" : "prune",
				      time_duration(hold));
		}
	}

	if (hold == 0) {
		change_state(JPNoInfo);
		return;
	}

	inner_update(join, hold);
}

pim_oif::interest pim_oif::get_local_interest() const {
	pim_interface *intf = pim_intf();

	if (intf && !intf->am_dr())
		return NoInfo;

	return m_local;
}

pim_oif::interest pim_oif::get_interest() const {
	return get_internal_interest(get_local_interest());
}

pim_oif::interest pim_oif::get_interest(bool includelocal) const {
	return get_internal_interest(includelocal ?
			get_local_interest() : pim_oif::NoInfo);
}

pim_oif::interest pim_oif::get_internal_interest(interest local) const {
	/* If no local interest, rely entirely in PIM state */
	if (local == NoInfo) {
		/* Both have no interest, so we have no interest */
		if (m_jpstate == JPNoInfo)
			return NoInfo;

		/* If PIM is in Pruned state, we want to Exclude */
		if (m_jpstate == Pruned || ((m_state->is_rpt() && !m_state->is_wildcard()) && (m_jpstate == PendingPrune)))
			return Exclude;

		/* all other states (Joined, PendingPrune) reflect Include */
		return Include;
	} else {
		/* As said above */
		if (m_jpstate == Joined || (!(m_state->is_rpt() && !m_state->is_wildcard()) && (m_jpstate == PendingPrune)))
			return Include;

		/* If PIM doesn't Include, we rely on the local state */
		return local;
	}
}

bool pim_oif::has_interest() const {
	return get_internal_interest(m_local) != NoInfo;
}

void pim_oif::dr_changed(bool islocal) {
	if (m_state->owner()->should_log(EVERYTHING)) {
		log().xprintf("DR-Changed event, interest is %s and i'm %s the RP\n",
			      _oif_interest(get_internal_interest(m_local)),
			      islocal ? "" : "no longer ");
	}

	/* we only care about DR events if we have local interest */
	if (m_local == NoInfo)
		return;

	interest prev = NoInfo;

	if (!islocal)
		prev = m_local;

	changed_state(get_internal_interest(prev));
}

void pim_oif::timed_out() {
	/* (*,G), (S,G) and (S,G,rpt) */
	change_state(JPNoInfo);
}

void pim_oif::output_info(base_stream &ctx) const {
	base_stream &os = ctx.write(m_intf->name());

	pim_interface *intf = pim_intf();

	if (m_local != NoInfo) {
		os.write(", Local");

		if (intf && !intf->am_dr())
			os.write(" (Not DR)");
	}

	if (m_timer.is_running()) {
		os.xprintf(", %{duration}", m_timer.time_left_d());
	}

	os.write(", ");
	switch (get_interest()) {
	case Include:
		os.write("Forwarding");
		break;
	case Exclude:
		os.write("Pruned");
		break;
	default:
		os.write("NoInfo");
		break;
	}

	output_extra_info(ctx);

	os.newl();
}

void pim_oif::output_extra_info(base_stream &ctx) const {
	/* empty */
}

pim_common_oif::pim_common_oif(pim_source_state_base *owner, interface *intf)
	: pim_oif(owner, intf),
	m_assert_timer("", this, std::mem_fun(&pim_common_oif::assert_timed_out)) {

	m_assert_timer.name = "pim assert timer ";
	m_assert_timer.name += intf->name();

	m_assert_state = AssertNoInfo;
	delete_assert_info();
}

bool pim_common_oif::has_interest() const {
	return m_assert_state != AssertNoInfo || pim_oif::has_interest();
}

static const char *_assert_state_name(pim_common_oif::assert_state state) {
	switch (state) {
	case pim_common_oif::AssertNoInfo:
		return "NoInfo";
	case pim_common_oif::LostAssert:
		return "LostAssert";
	case pim_common_oif::WonAssert:
		return "WonAssert";
	}

	return "Unknown";
}

pim_common_oif::assert_state pim_common_oif::current_assert_state() const {
	return m_assert_state;
}

pim_neighbour *pim_common_oif::assert_winner() const {
	return m_assert_winner;
}

void pim_common_oif::change_assert_state(pim_common_oif::assert_state newstate, bool propagate) {
	if (newstate == m_assert_state)
		return;

	interest prev = get_interest();

	if (m_state->owner()->should_log(EXTRADEBUG)) {
		log().xprintf("Changed ASSERT state %s -> %s\n",
			      _assert_state_name(m_assert_state),
			      _assert_state_name(newstate));
	}

	m_assert_state = newstate;

	if (m_assert_state == AssertNoInfo) {
		delete_assert_info();
	}

	if (propagate)
		changed_state(prev);
}

void pim_common_oif::store_assert_info(pim_neighbour *neigh, uint32_t metric, uint32_t pref) {
	bool notify = m_assert_winner != neigh;

	m_assert_winner = neigh;

	m_assert_winner_metric = metric;
	m_assert_winner_pref = pref;

	if (notify) {
		/* force rebuild of upstream path if neighbour changed */
		m_state->build_upstream_state();
	}
}

void pim_common_oif::restart_assert_timer() {
	m_assert_timer.start_or_update(pim_intf()->conf()->assert_timeout(), false);
}

void pim_common_oif::restart_assert_timer_minus_override() {
	m_assert_timer.start_or_update(pim_intf()->conf()->assert_timeout() - 3000, false);
}

void pim_common_oif::pp_timed_out() {
	change_state(JPNoInfo);
}

void pim_common_oif::delete_assert_info() {
	m_assert_winner = 0;
	m_assert_winner_pref = 0xffffffff;
	m_assert_winner_metric = 0xffffffff;

	m_assert_timer.stop();
}

void pim_common_oif::assert_timed_out() {
	if (m_assert_state == LostAssert) {
		change_assert_state(AssertNoInfo);
	} else if (m_assert_state == WonAssert) {
		((pim_source_state_common *)m_state)->send_assert(pim_intf());
		restart_assert_timer_minus_override();
	}
}

void pim_common_oif::inner_update(bool join, uint32_t hold) {
	if (join) {
		m_timer.start_or_update(hold, false);
		change_state(Joined);
	} else {
		if (m_jpstate == Joined) {
			uint32_t jpov = jp_override_interval();

			if (jpov > 0) {
				m_pp_timer.start_or_update(jpov, false);
				change_state(PendingPrune);
			} else {
				m_pp_timer.stop();
				change_state(JPNoInfo);
			}
		}
	}
}

pim_oif::interest pim_common_oif::get_internal_interest(pim_oif::interest local) const {
	if (m_assert_state == LostAssert) {
		return Exclude;
	}

	return pim_oif::get_internal_interest(local);
}

void pim_common_oif::output_extra_info(base_stream &ctx) const {
	if (m_assert_state != AssertNoInfo) {
		ctx.xprintf(" (%s)", m_assert_state == LostAssert ?
				"Lost Assert" : "Won Assert");
	}
}

pim_sg_rpt_oif::pim_sg_rpt_oif(pim_source_state_base *owner, interface *intf)
	: pim_oif(owner, intf) {
}

void pim_sg_rpt_oif::pp_timed_out() {
	change_state(Pruned);
}

void pim_sg_rpt_oif::inner_update(bool join, uint32_t hold) {
	if (join) {
		change_state(JPNoInfo);
	} else {
		if (m_jpstate == JPNoInfo) {
			uint32_t jpov = jp_override_interval();

			if (jpov > 0) {
				m_pp_timer.start_or_update(jpov, false);
				m_timer.start_or_update(hold, false);
				change_state(PendingPrune);
			} else {
				/* Short circuit the PrunePending state
				 * as jpov=0, which means either
				 * neigh_count <= 1 or the value is
				 * really that low */
				m_pp_timer.stop();
				m_timer.start_or_update(hold, false);
				change_state(Pruned);
			}
		} else if (m_jpstate == PendingPrune || m_jpstate == Pruned) {
			m_timer.start_or_update(hold, false);
		}
	}
}


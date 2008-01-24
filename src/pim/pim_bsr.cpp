/*
 * Multicast Routing Daemon (MRD)
 *   pim_bsr.cpp
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

#ifndef PIM_NO_BSR

#include <mrdpriv/pim/router.h>
#include <mrdpriv/pim/interface.h>
#include <mrdpriv/pim/group.h>
#include <mrdpriv/pim/neighbour.h>
#include <mrdpriv/pim/def.h>

#include <mrd/mrd.h>
#include <mrd/rib.h>

#include <unistd.h>
#include <errno.h>

#include <cstdlib>
#include <cmath>

enum {
	pim_rp_set_method_static = 9100,
};

static const method_info pim_rp_set_methods[] = {
	{ "static", "Adds a static entry to the RP set", pim_rp_set_method_static,
		false, property_def::NEGATE },
	{ 0 }
};

extern in6_addr pim_all_routers;

static const int BSRMinimumTimeBetweenBSMs = 10;
static const int BSRInitialCRPAdvCount = 3;
static const int BSRInitialCRPAdvPeriod = 3000;

pim_bsr::pim_bsr(pim_router *r)
	: m_bsr_timer("bootstrap timer", this, std::mem_fun(&pim_bsr::handle_bsr_timeout)),
	  m_sz_timer("sz timer", this, std::mem_fun(&pim_bsr::handle_sz_timeout)),
	  m_rp_adv_timer("rp adv timer", this, std::mem_fun(&pim_bsr::handle_rp_adv_timer)),
	  m_rp_set(r) {

	m_p_enable_bootstrap = r->instantiate_property_b("bootstrap", true);
	m_p_bsr_candidate = r->instantiate_property_b("bsr-candidate", false);
	m_p_bsr_priority = r->instantiate_property_u("bsr-priority", 128);
	m_p_bsr_timeout = r->instantiate_property_u("bsr-timeout", 2 * 60000 + 10000);
	m_p_bsr_period = r->instantiate_property_u("bsr-period", 60000);
	m_p_sz_timeout = r->instantiate_property_u("sz-timeout", 10 * (2 * 60000 + 10000));
	m_p_rp_candidate = r->instantiate_property_b("rp-candidate", false);
	m_p_rp_cand_prio = r->instantiate_property_u("rp-cand-priority", 192);
	m_p_rp_cand_adv_period = r->instantiate_property_u("rp-cand-adv-period", 60000);
	m_p_rp_cand_holdtime = r->instantiate_property_u("rp-cand-holdtime", 100);
	m_p_hashmask = r->instantiate_property_u("hashmask", 126);

	m_rp_set.set_hashmask(126);

	m_bsr_state = BSRPending;

	m_bsr_preferred_priority = 128;

	m_nc_bsr_state = NCNoInfo;

	m_last_sent_bsm = 0;
	m_rp_adv_count = 0;
}

bool pim_bsr::check_startup() {
	if (!m_rp_set.check_startup())
		return false;
	/* pim-router is registering one property */
	if (pim->m_properties.size() < 12)
		return false;

	return pim->add_child(&m_rp_set) != 0;
}

void pim_bsr::leaving() {
	send_leave_rp_candidate();
	send_leave_bootstrap();
}

void pim_bsr::shutdown() {
	m_rp_set.clear();
}

base_stream &pim_bsr::log() const {
	return pim->log().write("BSR, ");
}

void pim_bsr::acquired_primary_address() {
	if (m_p_bsr_candidate->get_bool())
		m_bsr_timer.start(bsr_rand_override(), false);
}

void pim_bsr::found_new_neighbour(pim_neighbour *neigh) {
	sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = neigh->localaddr();
	addr.sin6_scope_id = neigh->intf()->owner()->index();

	send_bootstrap_message(&addr);
}

in6_addr pim_bsr::rp_from_rpset(const inet6_addr &grpid) const {
	return m_rp_set.rp_for(grpid);
}

static inline const char *_bsr_state_name(pim_bsr::candidate_bsr_state state) {
	switch (state) {
	case pim_bsr::BSRPending:
		return "Pending";
	case pim_bsr::BSRCandidate:
		return "Candidate";
	case pim_bsr::BSRElected:
		return "Elected";
	default:
		return "Unknown";
	}
}

static inline const char *_no_cand_bsr_state_name(int name) {
	switch (name) {
	case pim_bsr::NCNoInfo:
		return "NoInfo";
	case pim_bsr::NCAcceptAny:
		return "AcceptAny";
	case pim_bsr::NCAcceptPreferred:
		return "AcceptPreferred";
	default:
		return "Unknown";
	}
}

void pim_bsr::output_info(base_stream &ctx) const {
	ctx.xprintf("Bootstrapping: %s", m_p_enable_bootstrap->get_bool() ?
					 "Enabled" : "Disabled");

	if (m_p_enable_bootstrap->get_bool()) {
		if (m_p_bsr_candidate->get_bool())
			ctx.write(", BSR-Candidate");
		if (m_p_rp_candidate->get_bool())
			ctx.write(", RP-Candidate");
	}

	ctx.newl();

	if (m_p_enable_bootstrap->get_bool()) {
		if (m_p_bsr_candidate->get_bool()) {
			ctx.xprintf("BSR-Priority: %u\n",
				    m_p_bsr_priority->get_unsigned());
		}

		if (m_p_rp_candidate->get_bool()) {
			ctx.xprintf("RP-Cand-Priority: %u\n",
				    m_p_rp_cand_prio->get_unsigned());
		}
	}

	bool printpref = true;

	if (m_p_bsr_candidate->get_bool()) {
		ctx.xprintf("BSR State: %s", _bsr_state_name(m_bsr_state));

		if (!m_bsr_timer.is_running())
			ctx.write(" (Not running)");
		else if (m_bsr_state != BSRElected)
			ctx.xprintf(" (for %{duration})", m_bsr_timer.time_left_d());

		ctx.newl();

		printpref = (m_bsr_state != BSRElected);
	} else {
		ctx.xprintf("BSR State: %s\n", _no_cand_bsr_state_name(m_nc_bsr_state));
	}


	if (printpref) {
		ctx.write("Preferred BSR: ");
		if (m_bsr_preferred.is_any())
			ctx.write("None");
		else
			ctx.write(m_bsr_preferred);
		ctx.newl();
	}

	m_rp_set.output_info(ctx, std::vector<std::string>());
}

void pim_bsr::handle_bootstrap_message(pim_interface *pif, const sockaddr_in6 *from,
		const sockaddr_in6 *dst, pim_bootstrap_message *msg, uint16_t len) {
	if (pim->should_log(MESSAGE_CONTENT)) {
		base_stream &os = log();
		os.inc_level();
		_debug_pim_dump(os, *msg, len);
		os.dec_level();
	}

	if (!m_p_enable_bootstrap->get_bool()) {
		/* Bootstrapping disabled */
		return;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr)
		&& (!pif->owner()->in_same_subnet(from->sin6_addr)
		    || !pif->get_neighbour(from->sin6_addr))) {
		/* Silent drop */
		return;
	}

	if (dst->sin6_addr == pim_all_routers) {
		if (!msg->no_forward()) {
			/*
			 * if (BSM.src_ip_address != RPF_neighbor(BSM.BSR_ip_address))
			 *	silent drop
			 */

			pim_neighbour *neigh = pim->get_rpf_neighbour(msg->bsr_address.addr);
			if (!neigh || !neigh->has_address(from->sin6_addr)) {
				/* Silent drop */
				return;
			}
		} else {
			/* XXX unimplemented */
			/*  } else if ((any previous BSM for this scope has been accepted) OR
             		(more than BS_Period has elapsed since startup)) {
				    #only accept no-forward BSM if quick refresh on startup
				    drop the Bootstrap message silently
				} */
		}
	} else if (g_mrd->has_address(dst->sin6_addr)) {
		/* XXX check for last reception, to see if
		 * this is a quick refresh on startup */
	} else {
		/* Silent drop */
		return;
	}

	bool ispref = is_bsr_preferred(msg);

	if (m_p_bsr_candidate->get_bool()) {
		if (ispref) {
			/* -> C-BSR state */
			switch_bsr_state(BSRCandidate);
			/* Forward BSM; Store RP-Set; Set Bootstrap Timer to BS_Timeout */
			accept_preferred_bsr(&msg->bsr_address.addr,
					msg->bsr_priority, msg, len);
		} else {
			if (m_bsr_state == BSRCandidate
				&& m_bsr_preferred == inet6_addr(msg->bsr_address.addr)) {
				to_pending_bsr();
			} else if (m_bsr_state == BSRElected) {
				if (!g_mrd->has_address(msg->bsr_address.addr))
					im_the_elected_bsr(true);
			}
		}
	} else {
		if (pim->should_log(INTERNAL_FLOW))
			log().xprintf("BSM is%s preferred.\n", ispref ? "" : " not");

		if (ispref || (m_nc_bsr_state == NCNoInfo
		     || m_nc_bsr_state == NCAcceptAny)) {
			/* -> AcceptPreferred state */
			change_nc_state(NCAcceptPreferred);

			/* Forward BSM; Store RP-Set; Set Bootstrap Timer to BS_Timeout */
			accept_preferred_bsr(&msg->bsr_address.addr,
					msg->bsr_priority, msg, len);

			/* Set SZT to SZ_Timeout */
			refresh_sz_timer();
		}
	}
}

void pim_bsr::change_nc_state(no_cand_bsr_state newstate) {
	if (m_nc_bsr_state == newstate)
		return;

	if (pim->should_log(EXTRADEBUG))
		log().xprintf("State changed %s -> %s\n",
			      _no_cand_bsr_state_name(m_nc_bsr_state),
			      _no_cand_bsr_state_name(newstate));

	m_nc_bsr_state = newstate;
}

void pim_bsr::handle_candidate_rp_adv(pim_interface *intf, const sockaddr_in6 *from,
					pim_candidate_rp_adv_message *msg, uint16_t len) {
	if (!is_bsr())
		return;

	std::list<inet6_addr> grps;

	pim_encoded_group_address *grp = msg->grps();
	for (uint8_t i = 0; i < msg->prefixcount; i++, grp++)
		grps.push_back(inet6_addr(grp->addr, grp->masklen));

	m_rp_set.update_entries(msg->rp_addr.addr, msg->priority,
				ntoh(msg->holdtime), grps);
}

void pim_bsr::broadcast_rp_set_changed(pim_rp_set *) const {
	mrd::group_list::const_iterator j = g_mrd->group_table().begin();

	for(; j != g_mrd->group_table().end(); ++j) {
		group_node *node = j->second->node_owned_by(pim);
		if (node) {
			((pim_group_node *)node)->rp_set_changed();
		}
	}
}

void pim_bsr::handle_bsr_timeout() {
	if (m_p_bsr_candidate->get_bool()) {
		switch (m_bsr_state) {
		case BSRCandidate:
			switch_bsr_state(BSRPending);
			m_bsr_timer.start(bsr_rand_override(), false);
			break;
		case BSRPending:
		case BSRElected:
			im_the_elected_bsr(true);
			break;
		}
	} else {
		/* -> AcceptAny state */
		change_nc_state(NCAcceptAny);

		/* XXX Refresh RP-Set */

		/* Remove BSR State */
		reset_preferred_bsr();
	}
}

void pim_bsr::handle_sz_timeout() {
	if (m_nc_bsr_state == NCAcceptAny) {
		sz_expired();
	}
}

bool pim_bsr::is_bsr_preferred(const pim_bootstrap_message *msg) const {
	return is_bsr_preferred(msg->bsr_address.addr, msg->bsr_priority);
}

bool pim_bsr::is_bsr_preferred(const in6_addr &from, int prio) const {
	/*
	 * ``A Bootstrap message is also preferred if it is from the
	 *   current BSR with a lower weight than the previous BSM it sent,
	 *   provided that if the router is a Candidate BSR the current BSR
	 *   still has a weight higher or equal than the router itself. In
	 *   this case, the "Current Bootstrap Router's BSR Priority" state
	 *   must be updated. (For lower weight, see Non-preferred BSM from
	 *   Elected BSR case.)''
	 *
	 * ``The weight of a BSR is defined to be the concatenation in
	 *   fixed-precision unsigned arithmetic of the BSR Priority field from
	 *   the Bootstrap message and the IP address of the BSR from the
	 *   Bootstrap message (with the BSR Priority taking the most-
	 *   significant bits and the IP address taking the least significant
	 *   bits).''
	 *
	 * We'll just check the priority first.
	 */

	if (!m_p_bsr_candidate->get_bool()) {
		if (prio == m_bsr_preferred_priority) {
			return from == m_bsr_preferred || from < m_bsr_preferred;
		}

		return prio > m_bsr_preferred_priority;
	}

	if (prio < m_bsr_preferred_priority) {
		if (prio >= (int)m_p_bsr_priority->get_unsigned())
			return true;
	} else if (prio == m_bsr_preferred_priority) {
		switch (m_bsr_state) {
		case BSRPending:
		case BSRElected:
			return from < pim->my_address();
		case BSRCandidate:
			return from < m_bsr_preferred || from == m_bsr_preferred;
		}
	}

	return prio > m_bsr_preferred_priority;
}

void pim_bsr::to_pending_bsr() {
	switch_bsr_state(BSRPending);

	reset_preferred_bsr();

	m_bsr_timer.start_or_update(bsr_rand_override(), false);
}

void pim_bsr::reset_preferred_bsr() {
	m_bsr_preferred = in6addr_any;
	m_bsr_preferred_priority = m_p_bsr_priority->get_unsigned();

	has_new_bsr(false);
}

void pim_bsr::im_the_elected_bsr(bool send) {
	candidate_bsr_state prevstate = m_bsr_state;

	if (m_bsr_state != BSRElected) {
		reset_preferred_bsr();

		switch_bsr_state(BSRElected);

		has_new_bsr(true);
	}

	if (prevstate != BSRElected || send)
		send_bootstrap_message(0);

	m_bsr_timer.start_or_update(m_p_bsr_period->get_unsigned(), false);
}

void pim_bsr::send_bootstrap_message(sockaddr_in6 *addr) const {
	if (!addr) {
		/* going to send all */
		time_t now = time(0);
		if ((now - m_last_sent_bsm) < BSRMinimumTimeBetweenBSMs)
			return;
	}

	pim_bootstrap_message *msg = g_mrd->opktb->header<pim_bootstrap_message>();

	uint16_t fragtag = mrd::get_randu32() & 0xffff;

	if (m_bsr_state == BSRElected)
		msg->construct(fragtag, m_rp_set.get_hashmask(),
				m_p_bsr_priority->get_unsigned(), pim->my_address());
	else if (m_bsr_state == BSRCandidate)
		msg->construct(fragtag, m_rp_set.get_hashmask(),
				m_bsr_preferred_priority, m_bsr_preferred);
	else
		return;

	uint16_t len = sizeof(pim_bootstrap_message);

	m_rp_set.build_message(msg, len);

	if (!addr)
		pim->send_all_neighbours(msg, len);
	else
		pim->sendmsg(0, addr, msg, len);

	m_last_sent_bsm = time(0);
}

void pim_bsr::send_leave_bootstrap() const {
	if (m_bsr_state == BSRElected) {
		pim_bootstrap_message *msg =
			g_mrd->opktb->header<pim_bootstrap_message>();

		msg->construct(mrd::get_randu32() & 0xffff, m_rp_set.get_hashmask(),
						0, pim->my_address());

		pim->send_all(msg, sizeof(pim_bootstrap_message));
	}
}

void pim_bsr::send_leave_rp_candidate() const {
	if (m_p_rp_candidate->get_bool() && m_bsr_state != BSRElected
			&& !m_bsr_preferred.is_any()) {
		pim_candidate_rp_adv_message *msg =
			g_mrd->opktb->header<pim_candidate_rp_adv_message>();

		msg->construct(0, m_p_rp_cand_prio->get_unsigned(), 0, pim->my_address());

		sockaddr_in6 addr = m_bsr_preferred.as_sockaddr();

		pim->sendmsg(0, &addr, msg, sizeof(pim_candidate_rp_adv_message));
	}
}

void pim_bsr::enable_rp_adv(const inet6_addr &grp, bool enable) {
	if (m_bsr_state == BSRElected) {
		std::list<inet6_addr> entries;
		entries.push_back(grp);

		m_rp_set.update_entries(pim->my_address(), m_p_rp_cand_prio->get_unsigned(),
				enable ? m_p_rp_cand_holdtime->get_unsigned() : 0, entries);
	} else {
		/* XXX if was enabled, send_leave_rp_candidate? */
	}
}

uint32_t pim_bsr::bsr_rand_override() const {
#if 1
	return (uint32_t)((5. + 2 * ::log((double)(1 + m_bsr_preferred_priority -
					m_p_bsr_priority->get_unsigned())) / ::log(2)) * 1000.);
#else
	return mrd::get_randu32() % 5000;
#endif
}

void pim_bsr::accept_preferred_bsr(const in6_addr *from, int prio,
				   pim_bootstrap_message *msg, uint16_t len) {
	if (!(m_bsr_preferred == inet6_addr(*from))) {
		bool was = m_bsr_preferred.is_any();

		m_bsr_preferred = *from;

		if (was && !m_bsr_preferred.is_any() && pim->should_log(NORMAL)) {
			log().xprintf("Bootstrap Router is at %{Addr}\n",
				      m_bsr_preferred);
		}

		has_new_bsr(false);
	}

	m_rp_set.store_from_message(*from, msg, len);

	m_bsr_preferred_priority = prio;

	pim->send_all_neighbours(msg, len);

	m_bsr_timer.start_or_update(m_p_bsr_timeout->get_unsigned(), false);
}

void pim_bsr::refresh_sz_timer() {
	m_sz_timer.start_or_update(m_p_sz_timeout->get_unsigned(), false);
}

void pim_bsr::sz_expired() {
	m_bsr_timer.stop();

	reset_preferred_bsr();
	// clear state
}

void pim_bsr::has_new_bsr(bool local) {
	m_rp_adv_timer.stop();

	if (!m_p_rp_candidate->get_bool())
		return;

	if (m_bsr_state == BSRElected || !m_bsr_preferred.is_any()) {
		m_rp_adv_count = BSRInitialCRPAdvCount;
		m_rp_adv_timer.start(mrd::get_randu32() % BSRInitialCRPAdvPeriod, true);
	}
}

void pim_bsr::handle_rp_adv_timer() {
	std::list<inet6_addr> entries = g_mrd->configured_group_set("pim");

	std::list<inet6_addr>::iterator i = entries.begin();

	while (i != entries.end()) {
		std::list<inet6_addr>::iterator j = i;
		++i;

		groupconf *gc = g_mrd->get_group_configuration(*j);
		if (gc) {
			pim_groupconf_node *pimgc =
				(pim_groupconf_node *)gc->get_child("pim");
			if (pimgc && pimgc->get_property_bool("rp_adv")) {
				continue;
			}
		}

		entries.erase(j);
	}

	if (m_rp_adv_count > 0) {
		m_rp_adv_count --;
		if (m_rp_adv_count == 0)
			m_rp_adv_timer.update(m_p_rp_cand_adv_period->get_unsigned(), true);
	}

	if (entries.empty())
		return;

	if (m_bsr_state == BSRElected) {
		m_rp_set.update_entries(pim->my_address(), m_p_rp_cand_prio->get_unsigned(),
					m_p_rp_cand_holdtime->get_unsigned(), entries);
	} else {
		pim_candidate_rp_adv_message *msg =
			g_mrd->opktb->header<pim_candidate_rp_adv_message>();

		msg->construct(entries.size(), m_p_rp_cand_prio->get_unsigned(),
				m_p_rp_cand_holdtime->get_unsigned(), pim->my_address());

		pim_encoded_group_address *grp = msg->grps();
		for (std::list<inet6_addr>::iterator i =
			entries.begin(); i != entries.end(); ++i, grp++) {
			grp->construct(*i);
		}

		sockaddr_in6 addr = m_bsr_preferred.as_sockaddr();

		pim->sendmsg(0, &addr, msg, msg->length());
	}
}

void pim_bsr::switch_bsr_state(candidate_bsr_state state) {
	if (m_bsr_state == state)
		return;

	if (pim->should_log(NORMAL)) {
		log().xprintf("State changed %s -> %s\n",
			      _bsr_state_name(m_bsr_state),
			      _bsr_state_name(state));
	}

	m_bsr_state = state;
}

pim_rp_set::pim_rp_set(pim_router *parent)
	: node(parent, "rp_set") {
}

bool pim_rp_set::check_startup() {
	if (!node::check_startup())
		return false;

	import_methods(pim_rp_set_methods);

	return true;
}

const char *pim_rp_set::description() const {
	return "RP-Set";
}

void pim_rp_set::set_hashmask(uint16_t mask) {
	m_hashmask = mask;
}

bool pim_rp_set::call_method(int id, base_stream &os,
			     const std::vector<std::string> &args) {
	if (id == pim_rp_set_method_static) {
		if (args.size() < 2)
			return false;
		inet6_addr grpaddr, rpaddr;
		int prio = 128;
		if (!grpaddr.set(args[0].c_str()) || !rpaddr.set(args[1].c_str()))
			return false;
		if (args.size() > 2) {
			char *end;
			prio = strtol(args[2].c_str(), &end, 10);
			if (*end || prio < 0 || prio > 0xff)
				return false;
		}

		return add_entry(grpaddr, rpaddr, prio, 100, true);
	} else {
		return node::call_method(id, os, args);
	}
}

bool pim_rp_set::add_entry(const inet6_addr &grp, const inet6_addr &rp,
			   uint8_t prio, uint16_t holdtime, bool _static) {
	group_set *g = m_db.search(grp);

	if (!g) {
		g = new group_set;
		if (!g)
			return false;

		g->prefix = grp;

		m_db.insert(g);
	}

	return g->add_entry(this, rp, prio, holdtime, _static);
}

bool pim_rp_set::group_set::add_entry(pim_rp_set *rpset, const in6_addr &rpaddr,
				      uint8_t prio, uint16_t holdtime, bool _static) {
	std::list<entry *>::iterator i = find(rpaddr);

	if (i != entries.end()) {
		if (_static)
			return false;

		bool changed = false;
		entry *ent = *i;

		if (ent->prio != prio) {
			entries.erase(i);
			ent->prio = prio;
			insert_entry(ent);
			changed = true;
		}

		ent->update_holdtime(holdtime);

		return changed;
	}

	entry *ent = new entry(rpset);

	ent->owner = this;
	ent->prio = prio;
	ent->rpaddr = rpaddr;
	ent->update_holdtime(holdtime, !_static);

	insert_entry(ent);

	if (pim->should_log(DEBUG)) {
		pim->log().xprintf("RP-Set, added to %{Addr}, RP: %{addr} [prio: %i, holdtime: %i secs]\n",
				   prefix, rpaddr, (int)prio, (int)holdtime);
	}

	return true;
}

bool pim_rp_set::remove_entry(const inet6_addr &grp, const inet6_addr &rp) {
	group_set *g = m_db.search(grp);

	if (g) {
		if (g->release_entry(grp, rp)) {
			if (g->entries.empty()) {
				m_db.remove(g);
				delete g;
			}
			return true;
		}
	}

	return false;
}

void pim_rp_set::update_entries(const inet6_addr &rpaddr, uint8_t prio,
			uint16_t holdtime, const std::list<inet6_addr> &grps) {
	int count = 0;
	for (std::list<inet6_addr>::const_iterator i =
			grps.begin(); i != grps.end(); ++i) {
		if (holdtime == 0) {
			if (remove_entry(*i, rpaddr))
				count++;
		} else {
			if (add_entry(*i, rpaddr, prio, holdtime, false))
				count++;
		}
	}

	if (count) {
		pim->bsr().send_bootstrap_message(0);

		pim->bsr().broadcast_rp_set_changed(this);
	}
}

static inline bool
bsm_is_valid_and_has_groups(const in6_addr &from,
	const pim_bootstrap_message *msg, uint16_t len)
{
	pim_bootstrap_group_def *grp = msg->grps();
	bool has_groups = false;

	for (uint32_t i = sizeof(pim_bootstrap_message);
			i < len; i += grp->length(), grp = grp->next()) {
		if ((i + grp->length()) > len) {
			/* badly formed packet */
			if (pim->should_log(MESSAGE_ERR))
				pim->bsr().log().xprintf("Received badly formed BSR message "
							 "from %{addr}, dropping.\n", from);

			return false;
		}

		if (grp->fragrp > 0)
			has_groups = true;
	}

	return has_groups;
}

void pim_rp_set::store_from_message(const in6_addr &from, pim_bootstrap_message *msg, uint16_t len) {
	/*
	 * ``The router uses the group-to-RP mappings contained in a BSM to
	 *   update its local RP-Set.
	 *
	 *   This action is skipped for an empty BSM. A BSM is empty if it
	 *   contains no group ranges, or if it only contains a single
	 *   group range where that group range has the Admin Scope Zone
	 *   bit set (a scoped BSM) and an RP count of zero.''
	 */

	/* check if message is empty, and if lengths are OK */
	if (!bsm_is_valid_and_has_groups(from, msg, len))
		return;

	pim_bootstrap_group_def *grp = msg->grps();
	m_hashmask = msg->hash_masklen;
	bool changed = false;

	for (uint32_t i = sizeof(pim_bootstrap_message);
			i < len; i += grp->length(), grp = grp->next()) {
		inet6_addr grpaddr(grp->grpaddr.addr, grp->grpaddr.masklen);

		group_set *g = m_db.search(grpaddr);

		pim_bootstrap_rp_record *rp = grp->rps();
		for (int j = 0; j < grp->fragrp; j++, rp++) {
			uint16_t holdtime = ntoh(rp->holdtime);

			if (holdtime == 0) {
				if (g) {
					g->release_entry(grpaddr, rp->addr.addr);
					changed = true;
				}
				continue;
			}

			if (!g) {
				g = new group_set;
				if (!g)
					continue;
				g->prefix = grpaddr;
				m_db.insert(g);
				changed = true;
			}

			entry *ent = 0;
			std::list<entry *>::iterator k = g->find(rp->addr.addr);
			if (k == g->entries.end()) {
				ent = new entry(this);
				if (!ent)
					continue;
				ent->owner = g;
				ent->prio = rp->priority;
				ent->rpaddr = rp->addr.addr;
				g->insert_entry(ent);
				changed = true;
			} else {
				ent = *k;
			}

			ent->update_holdtime(holdtime);
		}

		if (g) {
			std::list<entry *>::iterator k = g->entries.begin();

			while (k != g->entries.end()) {
				entry *ent = *k;
				++k;

				pim_bootstrap_rp_record *rp = grp->rps();

				for (uint8_t j = 0; j < grp->fragrp; j++, rp++) {
					if (rp->addr.addr == ent->rpaddr) {
						ent = 0;
						break;
					}
				}

				if (ent) {
					g->release_entry(grpaddr, ent->rpaddr);
					changed = true;
				}
			}

			if (g->entries.empty()) {
				m_db.remove(g);
				delete g;
			}
		}
	}

	if (changed)
		pim->bsr().broadcast_rp_set_changed(this);
}

void pim_rp_set::build_message(pim_bootstrap_message *msg, uint16_t &len) const {
	pim_bootstrap_group_def *grp = msg->grps();

	for (db::const_iterator i = m_db.begin(); i != m_db.end(); ++i) {
		grp->grpaddr.construct(i->prefix);
		grp->rpcount = grp->fragrp = i->entries.size();
		grp->resv = 0;
		pim_bootstrap_rp_record *rp = grp->rps();
		for (std::list<entry *>::const_iterator j = i->entries.begin();
						j != i->entries.end(); ++j) {
			rp->addr.construct((*j)->rpaddr);
			rp->holdtime = hton((*j)->holdtime);
			rp->priority = (*j)->prio;
			rp->resv = 0;
			rp++;
		}
		len += grp->length();
		grp = grp->next();
	}
}

int pim_rp_set::count_entries() const {
	int count = 0;
	for (db::const_iterator i = m_db.begin(); i != m_db.end(); ++i) {
		count += i->entries.size();
	}
	return count;
}

void pim_rp_set::clear() {
	db::iterator i;

	while ((i = m_db.begin()) != m_db.end()) {
		group_set *g = &(*i);

		for (std::list<entry *>::iterator j = g->entries.begin();
				j != g->entries.end(); ++j) {
			delete *j;
		}

		m_db.remove(g);
		delete g;
	}

	m_hashmask = pim->bsr().get_default_hashmask();
}

void pim_rp_set::handle_entry_timeout(entry * &ent) {
	group_set *g = ent->owner;

	std::list<entry *>::iterator i = g->find_entry(ent);

	if (i == ent->owner->entries.end())
		return;

	g->entries.erase(i);
	delete ent;

	if (g->entries.empty()) {
		m_db.remove(g);
		delete g;
	}

	pim->bsr().broadcast_rp_set_changed(this);
}

bool pim_rp_set::output_info(base_stream &ctx, const std::vector<std::string> &) const {
	ctx.writeline("RP-Set:");

	ctx.inc_level();

	for (db::const_iterator i = m_db.begin(); i != m_db.end(); ++i) {
		if (!i->entries.empty()) {
			ctx.write(i->prefix).writeline(":");
			ctx.inc_level();
			for (std::list<entry *>::const_iterator j =
				i->entries.begin(); j != i->entries.end(); ++j) {
				entry *ent = (*j);

				ctx.xprintf("RP %{addr}", ent->rpaddr);

				if (ent->timer.is_running())
					ctx.xprintf(" for %{duration}",
						    ent->timer.time_left_d());
				else
					ctx.write(", static,");

				ctx.xprintf(" prio: %i holdtime %{duration}\n",
					    (int)ent->prio, time_duration(ent->holdtime * 1000));
			}
			ctx.dec_level();
		}
	}

	if (m_db.empty())
		ctx.writeline("(None)");

	ctx.dec_level();

	return true;
}

pim_rp_set::entry::entry(pim_rp_set *rpset)
	: timer("rp set entry", rpset, std::mem_fun(&pim_rp_set::handle_entry_timeout), this) {
	prio = 0;
	holdtime = 0;
}

void pim_rp_set::entry::update_holdtime(uint16_t ht, bool andtimer) {
	holdtime = ht;
	if (andtimer)
		timer.start_or_update(holdtime * 1000, false);
}

uint8_t pim_rp_set::group_set::greater_prio() const {
	if (entries.empty())
		return 0xff;

	return (*entries.begin())->prio;
}

bool pim_rp_set::group_set::has_entry(entry *ent) const {
	return std::find(entries.begin(), entries.end(), ent) != entries.end();
}

bool pim_rp_set::group_set::release_entry(const inet6_addr &grpaddr,
				      const inet6_addr &rpaddr, bool verbose) {
	std::list<entry *>::iterator j = find(rpaddr);
	if (j != entries.end()) {
		if (!(*j)->timer.is_running()) {
			/* static */
			return false;
		}

		if (verbose && pim->should_log(pim->bsr().is_bsr() ? DEBUG : EXTRADEBUG)) {
			pim->log().xprintf("RP-Set %{Addr}, removed RP: %{Addr} [prio: %i]\n",
					   grpaddr, rpaddr, (int)(*j)->prio);
		}

		delete *j;
		entries.erase(j);

		return true;
	}

	return false;
}

std::list<pim_rp_set::entry *>::iterator pim_rp_set::group_set::find_entry(entry *ent) {
	return std::find(entries.begin(), entries.end(), ent);
}

std::list<pim_rp_set::entry *>::iterator pim_rp_set::group_set::find(const in6_addr &rp) {
	for (std::list<entry *>::iterator i = entries.begin();
				i != entries.end(); ++i) {
		if ((*i)->rpaddr == rp)
			return i;
	}
	return entries.end();
}

void pim_rp_set::group_set::insert_entry(entry *ent) {
	std::list<entry *>::iterator i = entries.begin();
	for (; i != entries.end(); ++i) {
		if ((*i)->prio > ent->prio)
			break;
	}

	entries.insert(i, ent);
}

static inline uint32_t _hash_ipv6(const in6_addr *addr) {
	return ((const uint32_t *)addr)[0] ^ ((const uint32_t *)addr)[1] ^
			((const uint32_t *)addr)[2] ^ ((const uint32_t *)addr)[3];
}

static inline uint32_t _one_hash(uint32_t _g, const in6_addr *addr) {
	uint32_t hash = _hash_ipv6(addr);

	/* Value(G,M,C(i)) =
	 * 	(1103515245 * ((1103515245 * (G&M)+12345) XOR C(i)) + 12345)
	 * 		mod 2^31 */

	return ((1103515245UL
			* ((1103515245UL * _g + 12345) ^ hash) + 12345) & 0x7fffffff);
}

inet6_addr pim_rp_set::rp_for(const inet6_addr &grp) const {
	group_set *g = m_db.longest_match(grp);

	while (g) {
		if (g->entries.empty()) {
			g = m_db.get_parent_node(g);
			continue;
		}

		entry *picked = *g->entries.begin();
		std::list<entry *>::iterator i = g->entries.begin();
		++i;

		in6_addr masked_group = grp.addr;
		if (m_hashmask < 128) {
			masked_group.s6_addr[m_hashmask / 8] &= 0xff << (8 - (m_hashmask % 8));
			for (int i = (m_hashmask + 7) / 8; i < 16; i++)
				masked_group.s6_addr[i] = 0;
		}

		uint32_t _g = _hash_ipv6(&masked_group);
		uint32_t best = _one_hash(_g, &picked->rpaddr);

		for (; i != g->entries.end(); ++i) {
			entry *potential = *i;

			if (potential->prio != picked->prio)
				break;

			uint32_t hash = _one_hash(_g, &potential->rpaddr);
			if (hash > best
				|| (hash == best && picked->rpaddr < potential->rpaddr)) {
				picked = potential;
				best = hash;
			}
		}

		return picked->rpaddr;
	}

	return in6addr_any;
}

#endif


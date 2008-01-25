/*
 * Multicast Routing Daemon (MRD)
 *   pim_group.cpp
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

bool pim_group_node::calculate_embedded_rp_addr(const in6_addr &addr, inet6_addr &dst) {
	if ((addr.s6_addr[1] & 0xf0) == 0x70) {
		if (addr.s6_addr[3] > 0 && addr.s6_addr[3] <= 64) {
			inet6_addr embrp(in6addr_any, addr.s6_addr[3]);

			memcpy(embrp.addr.s6_addr, addr.s6_addr + 4,
					(addr.s6_addr[3] + 7) / 8);
			embrp.addr.s6_addr[15] |= addr.s6_addr[2] & 0x0f;

			if (!embrp.matches(inet6_addr("ff80::/10"))
				&& !embrp.matches(inet6_addr("::/16"))
				&& !embrp.matches(inet6_addr("ff00::/8"))) {
				dst = embrp;
				return true;
			}
		}
	}

	return false;
}

pim_group_node::pim_group_node(router *rt, const inet6_addr &addr, pim_groupconf_node *conf)
	: group_node(rt), m_rp_path(this, std::mem_fun(&pim_group_node::rp_path_changed)), m_ssm(false),
		m_rp_failure_report_timer("rp failure report", this,
			std::mem_fun(&pim_group_node::report_forward_to_rp_failure), 15000, false) {

	m_addr = addr;
	m_rpaddr = in6addr_any;

	m_refcount = 0;

	m_wildcard = 0;

	// support embedded-RP mechanism

	const in6_addr *raddr = addr.address_p();

	bool R_bit = raddr->s6_addr[1] & 0x40;
	bool P_bit = raddr->s6_addr[1] & 0x20;
	bool T_bit = raddr->s6_addr[1] & 0x10;

	if (P_bit && T_bit) {
		if (R_bit) {
			calculate_embedded_rp_addr(addr.addr, m_embedded_rpaddr);
		} else if (raddr->s6_addr[3] == 0) {
			m_ssm = true;
		}
	}

	m_selfrp = false;

	m_mfa_inst = 0;

	m_conf = conf;

	m_rp_failure_count = 0;
	m_rp_failure_last_msg = 0;
}

pim_group_node::~pim_group_node() {
}

void pim_group_node::shutdown() {
	while (!m_states.empty()) {
		source_pair &p = m_states.begin()->second;

		pim_source_state_base *state = 0;

		if (p.first) {
			state = p.first;
			p.first = 0;
		} else {
			state = p.second;
			p.second = 0;
		}

		if (!p.first && !p.second)
			m_states.erase(m_states.begin());

		delete state;
	}

	delete m_wildcard;
	m_wildcard = 0;

	if (m_mfa_inst) {
		g_mrd->mfa()->release_group(m_mfa_inst);
		m_mfa_inst = 0;
	}

	if (pim->should_log(DEBUG))
		pim->log().xprintf("Removed group state for %{Addr}\n", id());
}

bool pim_group_node::output_info(base_stream &ctx, const std::vector<std::string> &args) const {
	ctx.writeline("PIM");

	ctx.inc_level();

	if (!is_ssm()) {
		ctx.write("Rendezvous-Point: ");

		if (IN6_IS_ADDR_UNSPECIFIED(&m_rpaddr)) {
			ctx.write("none");
		} else {
			ctx.xprintf("%{addr} [", m_rpaddr);
			switch (m_rp_source) {
			case rps_static:
				ctx.write("static");
				break;
			case rps_embedded:
				ctx.write("embedded");
				break;
			case rps_rp_set:
				ctx.write("rp-set");
				break;
			case rps_join:
				ctx.write("from join-prune");
				break;
			}

			if (is_self_rp())
				ctx.write(", self");
			ctx.write("]");
		}

		ctx.newl();
	}

	ctx.writeline("Sources:");

	ctx.inc_level();

	if (m_states.empty() && !m_wildcard)
		ctx.writeline("(None)");
	else {
		if (m_wildcard)
			m_wildcard->output_info(ctx);

		for (states::const_iterator i = m_states.begin();
				i != m_states.end(); ++i) {
			if (i->second.first)
				i->second.first->output_info(ctx);
			if (i->second.second)
				i->second.second->output_info(ctx);
		}
	}

	ctx.dec_level();

	ctx.dec_level();

	return true;
}

void pim_group_node::set_rp() {
	rp_source src;

	inet6_addr newrp = rp_for_group(src);

	set_rp(newrp, src);
}

void pim_group_node::set_rp(const inet6_addr &rp, rp_source src) {
	if (m_ssm)
		return;

	if (rp.is_any())
		return;

	if (!(m_rpaddr == rp)) {
		if (should_log(DEBUG)) {
			if (IN6_IS_ADDR_UNSPECIFIED(&m_rpaddr)) {
				if (g_mrd->has_address(rp))
					log().writeline("I'm the RP for this group");
				else
					log().xprintf("RP is at %{Addr}\n", rp);
			} else {
				log().xprintf("Changing RP from %{addr} to %{Addr}\n", m_rpaddr, rp);
			}
		}

		m_rpaddr = rp;
		m_rp_source = src;
		m_selfrp = g_mrd->has_address(rp);

		/* reset failure info */
		m_rp_failure_count = 0;
		m_rp_failure_last_msg = 0;
		m_rp_failure_report_timer.stop();

		if (m_selfrp)
			m_rp_path.release();
		else
			m_rp_path.set_destination(rp);

		if (m_wildcard)
			m_wildcard->rp_changed();

		states::iterator i = m_states.begin();

		while (i != m_states.end()) {
			/* call rp_changed for RPT state first as it doesnt
			 * cause state removal. */
			if (i->second.second)
				i->second.second->rp_changed();
			pim_group_source_state *st = i->second.first;
			/* From STL docs: ``Erasing an element from a map also
			 * does not invalidate any iterators, except, of
			 * course, for iterators that actually point to the
			 * element that is being erased''. */
			++i;
			if (st)
				st->rp_changed();
		}
	}
}

void pim_group_node::rp_path_changed(uint32_t) {
	if (m_rp_path.valid && should_log(EXTRADEBUG)) {
		log().writeline("RP path changed");
	}
}

inet6_addr pim_group_node::rp_for_group(rp_source &src) const {
	if (m_conf) {
		in6_addr rpaddr;

		if (m_conf->rp_for_group(id(), rpaddr, src))
			return rpaddr;
	}

	return in6addr_any;
}

void pim_group_node::rp_set_changed() {
	if (m_ssm)
		return;

	set_rp();
}

bool pim_group_node::attach(group *node, const pim_groupconf_node *entry) {
	node->attach_node(this);

	return true;
}

address_set pim_group_node::source_state_set() const {
	address_set res;
	for (states::const_iterator i = m_states.begin(); i != m_states.end(); i++) {
		res.insert(i->first);
	}

	return res;
}

address_set pim_group_node::local_source_state_set() const {
	address_set res;
	for (states::const_iterator i = m_states.begin(); i != m_states.end(); i++) {
		if (i->second.first && i->second.first->is_source_local())
			res.insert(i->first);
	}

	return res;
}

void pim_group_node::subscriptions_changed(const group_interface *gif,
		group_interface::event_type event, const address_set &sources) {
	if (gif->filter_mode() == group_interface::include) {
		if (event == group_interface::added_sources) {
			for (address_set::const_iterator i = sources.begin(); i != sources.end(); ++i) {
				/* if source host is joining isn't local */
				if (!gif->intf()->in_same_subnet(*i)) {
					/* join it, possibly creating the (S,G) state
					 * if it doesn't exist */
					create_state(*i, false, gif->intf(), true);
				}
			}
		} else if (event == group_interface::removed_sources) {
			for (address_set::const_iterator i = sources.begin(); i != sources.end(); ++i) {
				pim_group_source_state *state = get_state(*i);
				if (state) {
					state->release_oif(gif->intf(), true);
				}
			}
		} else if (event == group_interface::all_sources) {
			if (m_wildcard) {
				m_wildcard->release_oif(gif->intf(), true);
			}

			address_set sss = source_state_set();
			address_set added, removed;

			sss.assign_with(gif->include_set(), added, removed);

			for (address_set::const_iterator i = added.begin(); i != added.end(); ++i) {
				/* if the joining new source isn't local */
				if (!gif->intf()->in_same_subnet(*i)) {
					/* join it, possibly creating the (S,G) state
					 * if it doesn't exist */
					create_state(*i, false, gif->intf(), true);
				}
			}

			for (address_set::const_iterator i = removed.begin(); i != removed.end(); ++i) {
				pim_group_source_state *state = get_state(*i);
				if (state) {
					state->release_oif(gif->intf(), true);
				}
			}
		}
	} else {
		/* join the (*,G) in interface gif, creates
		 * the wildcard state if it doesn't exist */
		create_wildcard(gif->intf(), true, 0);

		if (event == group_interface::all_sources) {
			address_set sss = source_state_set();

			sss.union_with(gif->exclude_set());

			for (address_set::const_iterator i = sss.begin(); i != sss.end(); ++i) {
				if (!gif->intf()->in_same_subnet(*i)) {
					pim_source_state_base *state = create_state(*i, false);

					if (state) {
						if (gif->exclude_set().has_addr(*i)) {
							state->set_local_oif(gif->intf(), false);
						} else {
							state->release_oif(gif->intf(), true);
						}
					}
				}
			}
		} else if (event == group_interface::added_sources) {
			for (address_set::const_iterator i = gif->exclude_set().begin();
						i != gif->exclude_set().end(); ++i) {
				if (!gif->intf()->in_same_subnet(*i)) {
					pim_source_state_base *state = create_state(*i, false);
					if (state) {
						// Prune the interface
						state->set_local_oif(gif->intf(), false);
					}
				}
			}
		} else {
			for (address_set::const_iterator i = sources.begin(); i != sources.end(); ++i) {
				pim_group_source_state *state = get_state(*i);
				if (state) {
					state->release_oif(gif->intf(), true);
				}
			}
		}
	}
}

bool pim_group_node::check_startup() {
	m_mfa_inst = g_mrd->mfa()->create_group(pim, id(), this);

	if (!m_mfa_inst)
		return 0;

	m_mfa_inst->activate(true);

	return group_node::check_startup();
}

void pim_group_node::attached(group *grp) {
	group_node::attached(grp);

	if (!check_startup()) {
		if (should_log(WARNING))
			log().writeline("Failed to attach PIM group");
		grp->dettach_node(this);
		delete this;
		return;
	}

	m_conf->attach_watcher(this);
}

void pim_group_node::dettached() {
	m_conf->dettach_watcher(this);

	shutdown();

	group_node::dettached();
}

void pim_group_node::garbage_collect() {
	/* Refresh KATs based on forwarding activity */
	for (states::const_iterator i = m_states.begin(); i != m_states.end(); ++i) {
		/* check non-RPT state */
		if (i->second.first && i->second.first->m_kat_enabled) {
			i->second.first->update_fw_counters();
		}
	}

	tval now = tval::now();

	pim_intfconf_node *defconf = (pim_intfconf_node *)
		g_mrd->default_interface_configuration()->get_child("pim");

	uint32_t defval = defconf ? defconf->data_timeout() : 210000;

	/* Timeout states based on KAT */
	for (states::const_iterator i = m_states.begin(); i != m_states.end(); ++i) {
		if (i->second.first && i->second.first->m_kat_enabled) {
			pim_group_source_state *st = i->second.first;

			pim_interface *iif = pim->get_interface(st->iif());

			uint32_t val = iif ? iif->conf()->data_timeout() : defval;

			uint32_t diff = now - st->m_kat_last_update;

			if (val <= diff) {
				st->m_kat_enabled = false;
				if (!handle_kat_expired(st))
					break;
			}
		}
	}
}

bool pim_group_node::has_interest_in_group() const {
	if (!m_states.empty()) {
		for (states::const_iterator i = m_states.begin(); i != m_states.end(); ++i) {
			if (i->second.first && i->second.first->state_desired())
				return true;
			if (i->second.second && i->second.second->state_desired())
				return true;
		}
	}

	return m_wildcard && m_wildcard->state_desired();
}

pim_source_state_base *pim_group_node::create_state(const inet6_addr &addr, bool rpt) {
	return create_state(addr, rpt, 0, false, 0);
}

pim_source_state_base *pim_group_node::create_state(const inet6_addr &addr, bool rpt,
					interface *oif, bool local, uint32_t val) {
	if (addr.is_any())
		return create_wildcard(oif, local, val) ? m_wildcard : 0;

	states::const_iterator i = m_states.find(addr);

	pim_source_state_base *state = i != m_states.end() ?
			(rpt ? i->second.second : (pim_source_state_base *)i->second.first) : 0;

	bool created = false;

	if (!state) {
		if (!rpt)
			state = create_source_state(addr);
		else
			state = create_source_rpt_state(addr);

		if (!state || !state->check_startup()) {
			delete state;
			return 0;
		}

		if (!rpt)
			m_states[addr].first = (pim_group_source_state *)state;
		else
			m_states[addr].second = (pim_group_source_rpt_state *)state;

		if (m_wildcard)
			state->wildcard_state_existance_changed(true);

		created = true;
	}

	if (oif) {
		if (local)
			state->set_local_oif(oif);
		else
			state->set_oif(oif, val);
	}

	if (created) {
		state->check_upstream_path();

		if (should_log(VERBOSE))
			log().xprintf("Created state (%{addr}%s).\n", state->addr(),
				      rpt ? ", RPT" : "");
	}

	return state;
}

pim_source_state_base *pim_group_node::get_state(const inet6_addr &addr, bool rpt) const {
	states::const_iterator i = m_states.find(addr);

	if (i != m_states.end())
		return rpt ? i->second.second : (pim_source_state_base *)i->second.first;

	return 0;
}

void pim_group_node::remove_state(pim_source_state_base *st) {
	if (!st)
		return;

	bool remove = false;

	if (m_wildcard == st) {
		m_wildcard = 0;
		remove = true;

		/* safeguard group instance */
		m_refcount ++;

		states::iterator i = m_states.begin();
		while (i != m_states.end()) {
			pim_group_source_state *state = i->second.first;
			pim_group_source_rpt_state *rptstate = i->second.second;
			++i;

			if (rptstate)
				rptstate->wildcard_state_existance_changed(false);
			if (state)
				state->wildcard_state_existance_changed(false);
		}

		m_refcount --;

	} else {
		states::iterator i = m_states.begin();

		while (i != m_states.end()) {
			if (i->second.first == st) {
				i->second.first = 0;
				remove = true;
			} else if (i->second.second == st) {
				i->second.second = 0;
				remove = true;
			}

			if (!i->second.first && !i->second.second) {
				states::iterator j = i;
				++i;
				m_states.erase(j);
			} else {
				++i;
			}
		}
	}

	if (remove) {
		if (should_log(VERBOSE)) {
			base_stream &os = log().write("Removed ");
			st->output_name(os);
			os.writeline(" state");
		}

		delete st;

		if (m_states.empty() && m_refcount == 0) {
			owner()->someone_lost_interest();
		}
	}
}

bool pim_group_node::create_wildcard(interface *oif, bool local, uint32_t val) {
	if (m_ssm)
		return false;

	bool created = false;

	if (!m_wildcard) {
		m_wildcard = create_wildcard_state();

		if (!m_wildcard)
			return false;

		if (!m_wildcard->check_startup()) {
			delete m_wildcard;
			m_wildcard = 0;
			return false;
		}

		if (should_log(VERBOSE))
			log().writeline("Created state (*, G).");

		created = true;
	}

	if (oif) {
		if (local)
			m_wildcard->set_local_oif(oif);
		else
			m_wildcard->set_oif(oif, val);
	}

	if (created) {
		m_wildcard->check_upstream_path();

		for (states::iterator i = m_states.begin(); i != m_states.end(); ++i) {
			if (i->second.first)
				i->second.first->wildcard_state_existance_changed(true);
			if (i->second.second)
				i->second.second->wildcard_state_existance_changed(true);
		}

		/* Force cached entries to be re-add */
		owner()->broadcast_source_interest_change(this);
	}

	return true;
}

bool pim_group_node::create_wildcard() {
	return create_wildcard(0, false, 0);
}

bool pim_group_node::has_wildcard() const {
	return m_wildcard != 0;
}

pim_group_wildcard_state *pim_group_node::wildcard() const {
	return m_wildcard;
}

void pim_group_node::dr_changed(pim_interface *intf, bool islocal) {
	if (m_wildcard)
		m_wildcard->dr_changed(intf, islocal);

	for (states::iterator i = m_states.begin(); i != m_states.end(); ++i) {
		if (i->second.first)
			i->second.first->dr_changed(intf, islocal);
		if (i->second.second)
			i->second.second->dr_changed(intf, islocal);
	}
}

void pim_group_node::do_register(const in6_addr *from, ip6_hdr *hdr,
				 uint16_t pktlen, bool null) {
	if (m_ssm)
		return;

	if (is_self_rp()) {
		hdr->ip6_hlim--;

		/* XXX maybe cache ACL accept value in source state? */
		if (!rp_acl_accept_source(hdr->ip6_src)) {
			int opt = get_conf()->rp_rejected_source_policy();

			if (opt == pim_groupconf_node::RPRejRegisterStop) {
				send_register_stop_to_router(hdr->ip6_src, *from);
			} else if (opt == pim_groupconf_node::RPRejSilentIgnore) {
				/* do nothing */
			} else if (opt == pim_groupconf_node::RPRejLogIgnore) {
				if (should_log(DEBUG)) {
					log().xprintf("Source Register ACL "
						      "rejected message for "
						      "%{addr} from DR %{addr}"
						      "\n", hdr->ip6_src, *from);
				}
			}
		}

		// always switch to SPT
		pim_group_source_state *state =
			(pim_group_source_state *)create_state(hdr->ip6_src, false);
		if (!state) {
			return;
		}

		/* This source is alive */
		state->restart_kat();

		/* XXX Send Register-Stops if InheritedOifs are empty too */
		if (state->spt() || state->count_oifs() == 0) {
			state->trigger_register_stop(from);
		} else if (!rp_acl_accept(*from)) {
			state->trigger_register_stop(from);
		} else if (!null && has_wildcard()) {
			/* draft11 says we should rejoin the normal packet
			 * forwarding flow here, but that doesn't really
			 * follow our model, so let's forward to
			 * inherited_olist(S,G,rpt) here
			 *
			 * inherited_olist(S,G,rpt) =
			 *      (joins(*,G) (-) prunes(S,G,rpt))
			 *  (+) (pim_include(*,G) (-) pim_exclude(S,G))
			 *  (-) (lost_assert(*,G) (+) lost_assert(S,G,rpt))
			 * */

			const pim_source_state_base::oifs *inhoifs = wildcard()->get_oifs();

			for (pim_source_state_base::oifs::const_iterator i =
					inhoifs->begin(); i != inhoifs->end(); ++i) {
				/* the presence of a Intf in inhoifs precludes
				 * that there is joins(*,G) or pim_include(*,G) */

				/* checks joins(*,G), pim_include(*,G) and lost_assert(*,G) */
				if ((*i)->get_interest() != pim_oif::Include)
					continue;

				pim_common_oif *oif =
					(pim_common_oif *)state->get_oif((*i)->intf());

				if (!oif || oif->get_local_interest() == pim_oif::Exclude
					|| state->lost_assert_rpt(oif))
					continue;

				state->forward((*i)->intf(), hdr, pktlen);
			}
		}
	} else {
		send_register_stop_to_router(hdr->ip6_src, *from);
	}
}

void pim_group_node::send_register_stop_to_router(const in6_addr &src, const in6_addr &from) const {
	if (is_self_rp()) {
		pim->send_register_stop_to_router(id(), rpaddr(), src, from);
	} else {
		pim->send_register_stop_to_router(id(), pim->my_address().address(),
						  src, from);
	}
}

bool pim_group_node::rp_acl_accept(const in6_addr &from) const {
#if 0
	if (m_conf->get_value("rp_acl")->as<rp_access>() != rpa_any) {
		bool accepted = false;

		const std::vector<inet6_addr> acls =
			m_conf->get_value("rp_acls")->as<std::vector<inet6_addr> >();

		for (std::vector<inet6_addr>::const_iterator i = acls.begin();
					!accepted && i != acls.end(); i++) {
			accepted = i->matches(*from);
		}

		if ((m_conf->get_value("rp_acl")->as<rp_access>() == rpa_allow && !accepted) ||
			(m_conf->get_value("rp_acl")->as<rp_access>() == rpa_deny && accepted)) {
			state->trigger_register_stop(from);
			return;
		}
	}
#endif

	/* Always accept for now */
	return true;
}

bool pim_group_node::rp_acl_accept_source(const in6_addr &src) const {
	return get_conf()->rp_source_acl_accepts(this, src);
}

void pim_group_node::register_stop(const inet6_addr &rpaddr, const inet6_addr &addr) {
	if (rpaddr == m_rpaddr) {
		pim_group_source_state *state = get_state(addr);
		if (state)
			state->register_stop();
	} else if (should_log(EXTRADEBUG)) {
		log().xprintf("Register Stop discarded, source is not the RP "
			      "(expected %{addr} got %{Addr})\n", m_rpaddr, rpaddr);
	}
}

void pim_group_node::clear_interface_references(interface *intf) {
	if (m_wildcard) {
		m_wildcard->grab();
		m_wildcard->clear_interface_references(intf);
	}

	states::iterator i = m_states.begin();

	while (i != m_states.end()) {
		pim_group_source_state *nonrpt = i->second.first;
		pim_group_source_rpt_state *rpt = i->second.second;

		/* safeguard our iterator */
		++i;

		/* RPT */
		if (rpt) {
			rpt->grab();
			rpt->clear_interface_references(intf);
		}
		if (nonrpt) {
			nonrpt->grab();
			nonrpt->clear_interface_references(intf);
		}
	}

	/* safeguard the group instance */
	m_refcount ++;

	i = m_states.begin();

	while (i != m_states.end()) {
		pim_group_source_state *nonrpt = i->second.first;
		pim_group_source_rpt_state *rpt = i->second.second;

		/* safeguard our iterator */
		++i;

		if (rpt)
			rpt->release();
		if (nonrpt)
			nonrpt->release();
	}

	if (m_wildcard) {
		m_wildcard->release();
	}

	m_refcount --;

	if (m_states.empty() && !m_wildcard) {
		owner()->someone_lost_interest();
	}
}

bool pim_group_node::handle_kat_expired(pim_group_source_state *state) {
	if (should_log(DEBUG))
		log().xprintf("state (%{addr}) KAT expired after %{duration}\n",
			      state->addr(), time_duration(state->uptime()));

	return state->check_interest();
}

void pim_group_node::found_new_neighbour(pim_neighbour *neigh) const {
	if (m_wildcard)
		m_wildcard->found_new_neighbour(neigh);

	for (states::const_iterator i = m_states.begin(); i != m_states.end(); ++i) {
		if (i->second.first)
			i->second.first->found_new_neighbour(neigh);
		/* RPT states don't care about new neighbours */
	}
}

void pim_group_node::lost_neighbour(pim_neighbour *neigh) const {
	for (states::const_iterator i = m_states.begin(); i != m_states.end(); ++i) {
		if (i->second.first)
			i->second.first->neighbour_lost(neigh);
		/* RPT states don't care about lost neighbours */
	}
	if (m_wildcard)
		m_wildcard->neighbour_lost(neigh);
}

void pim_group_node::rpt_upstream_changed() {
	for (states::const_iterator i = m_states.begin(); i != m_states.end(); ++i) {
		/* update (S,G,rpt) upstream */
		if (i->second.second)
			i->second.second->build_upstream_state();
	}
}

void pim_group_node::rpt_update_upstream() {
	for (states::const_iterator i = m_states.begin(); i != m_states.end(); ++i) {
		/* update (S,G,rpt) upstream */
		if (i->second.second)
			i->second.second->update_upstream();
	}
}

void pim_group_node::inherited_oif_changed_state(pim_oif *oif, pim_oif::interest prev) {
	/* safeguard the integrity of the group */
	m_refcount ++;

	states::iterator i = m_states.begin();

	while (i != m_states.end()) {
		pim_group_source_state *st = i->second.first;
		++i;

		if (st) {
			/* we set final=false as we don't want this call
			 * to remove the group state while we are iterating */
			st->inherited_oif_changed_state(oif, prev);
		}

		/* the RPT state has no interest in inherited oifs here */
	}

	m_refcount --;
	owner()->someone_lost_interest();
}

void pim_group_node::forward_to_rp(pim_group_source_state *state,
				interface *iif, ip6_hdr *hdr, uint16_t len) {
	if (!has_rp())
		return;

	const inet6_addr &from = pref_source_towards_rp();

	if (!has_rp_path() || from.is_any() || from.address() == in6addr_loopback) {
		failed_to_forward_to_rp("No available unicast path to RP");
		return;
	}

	g_mrd->opktb->send_offset = 0;

	pim_register_message *msg = g_mrd->opktb->header<pim_register_message>();
	memset(msg, 0, sizeof(*msg));

	memcpy(msg->ip6_header(), hdr, len);

	msg->construct(false, false);

	if (pim->send_register(from, rpaddr(), msg, len)) {
		state->restart_kat();
	} else {
		failed_to_forward_to_rp(0);
	}
}

void pim_group_node::failed_to_forward_to_rp(const char *msg) {
	m_rp_failure_count++;

	if (m_rp_failure_report_timer.is_running()) {
		if (msg == m_rp_failure_last_msg) {
			return;
		} else {
			m_rp_failure_report_timer.stop();
		}
	}

	if (should_log(DEBUG)) {
		base_stream &os = log();
		os.xprintf("Failed to register a multicast packet to RP %{addr}",
			   m_rpaddr);
		if (msg)
			os.xprintf(", %s", msg);
		os.newl();
	}

	m_rp_failure_last_msg = msg;

	m_rp_failure_report_timer.start();
}

void pim_group_node::report_forward_to_rp_failure() {
	if (!m_rp_failure_count)
		return;

	if (should_log(DEBUG)) {
		base_stream &os = log();
		os.xprintf("Failed to register %u multicast packets to RP "
			   "%{addr} in the last 15 seconds",
			   m_rp_failure_count, m_rpaddr);
		if (m_rp_failure_last_msg)
			os.xprintf(", %s", m_rp_failure_last_msg);
		os.newl();
	}

	m_rp_failure_count = 0;
	m_rp_failure_report_timer.start();
}

void pim_group_node::property_changed(node *n, const char *name) {
	if (!strcmp(name, "rp")) {
		set_rp();
	}
}

bool pim_group_node::has_interest_on(const in6_addr &src) const {
	/* Handles local interest */
	if (owner()->has_interest_on(src))
		return true;

	/* Handles (*,G) needs */
	if (has_wildcard()) {
		return wildcard()->get_downstream_interest() == pim_oif::Include;
	}

	return false;
}

void pim_group_node::discovered_source(interface *input,
				       const inet6_addr &sourceaddr,
				       source_discovery_origin *origin) {
	bool same = g_mrd->in_same_subnet(sourceaddr);
	bool inter = has_interest_on(sourceaddr);

	if (should_log(MESSAGE_SIG)) {
		log().xprintf("Discovered Source %{Addr} from %s InSameSubnet("
			      "%b) HasLocalInterest(%b)%s.\n", sourceaddr,
			      origin ? origin->origin_description() : "(unknown)",
			      same, inter, !same && !inter ?
			      ", state not being created" : "");
	}

	if (!same && !inter)
		return;

	/* XXX match input with RPF(S) */

	pim_group_source_state *state =
		(pim_group_source_state *)create_state(sourceaddr, false);

	if (!state) {
		/* XXX */
	}
}

bool pim_group_node::has_downstream_interest(const in6_addr &src) const {
	states::const_iterator i = m_states.find(src);

	if (i == m_states.end() || !i->second.first)
		return false;

	if (i->second.first->is_source_local()) {
		if (i->second.first->has_downstream_interest(true))
			return true;
	}

	return false;
}

pim_group_source_state *pim_group_node::create_source_state(const inet6_addr &addr) {
	return new pim_group_source_state(this, addr);
}

pim_group_source_rpt_state *pim_group_node::create_source_rpt_state(const inet6_addr &addr) {
	return new pim_group_source_rpt_state(this, addr);
}

pim_group_wildcard_state *pim_group_node::create_wildcard_state() {
	return new pim_group_wildcard_state(this);
}


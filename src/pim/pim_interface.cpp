/*
 * Multicast Routing Daemon (MRD)
 *   pim_interface.cpp
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

#include <errno.h>

#include <mrd/mrd.h>
#include <mrd/log.h>

#include <mrdpriv/pim/interface.h>
#include <mrdpriv/pim/router.h>
#include <mrdpriv/pim/group.h>
#include <mrdpriv/pim/neighbour.h>

extern in6_addr pim_all_routers;
extern sockaddr_in6 pim_all_routers_addr;

enum {
	pim_intf_method_flap = 1000,
	pim_intf_method_force_timeout
};

static const method_info pim_intf_methods[] = {
	{ "flap", 0, pim_intf_method_flap, false, 0 },
	{ "force-timeout", "Forces the timeout of a neighbor",
		pim_intf_method_force_timeout, false, 0 },
	{ 0 }
};

enum {
	AllCount,
	HelloCount,
	JoinPruneCount,
	AssertCount,
	BootstrapCount,
	CandRPCount,
	RegisterCount,
	RegisterStopCount,
	MessageCount
};

enum {
	RX = 0,
	TX,
	Bad
};

static const char *stats_descriptions[] = {
	"All",
	"Hello",
	"Join/Prune",
	"Assert",
	"Bootstrap",
	"Cand-RP",
	"Register",
	"RegisterStop",
};

pim_interface::pim_interface()
	: interface_node(pim), m_stats(this, MessageCount, stats_descriptions),
	  hello_timer_id("pim hello timer", this, std::mem_fun(&pim_interface::send_hello)) {

	intf_state = NOT_READY;

	gen_id = mrd::get_randu32();

	elected_dr = 0;
	m_landelay_enabled = true;
}

pim_interface::~pim_interface() {
}

bool pim_interface::check_startup() {
	if (!m_stats.setup())
		return false;

	m_stats.disable_counter(AllCount, TX);
	m_stats.disable_counter(RegisterCount, TX);
	m_stats.disable_counter(RegisterStopCount, TX);

	if (!interface_node::check_startup())
		return false;
	import_methods(pim_intf_methods);
	return true;
}

void pim_interface::attached(interface *intf) {
	interface_node::attached(intf);

	((conf_node *)conf())->attach_watcher(this);

	char tmrname[128];

	snprintf(tmrname, sizeof(tmrname), "pim hello timer (%s)", owner()->name());

	hello_timer_id.name = tmrname;

	update_hello_interval(conf()->hello_interval());

	check_lan_delay();
}

void pim_interface::shutdown() {
	if (get_state() != NOT_READY)
		send_hellox(0);

	neighbours_def n = neighbours;

	neighbours.clear();

	for (neighbours_def::const_iterator j = n.begin(); j != n.end(); ++j) {
		pim->lost_neighbour(*j);
		(*j)->shutdown();
		delete *j;
	}

	((conf_node *)conf())->dettach_watcher(this);

	owner()->dettach_node(this);
}

bool pim_interface::output_info(base_stream &ctx, bool extended) const {
	if (get_state() == NOT_READY)
		return false;

	ctx.writeline("PIM");

	ctx.inc_level();

	ctx.xprintf("DR Priority: %u\n", conf()->dr_priority());
	ctx.xprintf("LAN Propagation Delay: %ums Override Interval: %ums\n",
		    conf()->propagation_delay(), conf()->override_interval());

	if (elected_dr)
		ctx.xprintf("DR: %{Addr}\n", elected_dr->localaddr());
	else
		ctx.writeline("DR: self");

	ctx.writeline("Neighbours:");

	ctx.inc_level();

	if (neighbours.empty()) {
		ctx.writeline("(None)");
	} else {
		for (neighbours_def::const_iterator j = neighbours.begin();
						j != neighbours.end(); j++) {
			(*j)->output_info(ctx, extended);
		}
	}

	ctx.dec_level();

	ctx.dec_level();

	return true;
}

bool pim_interface::output_info(base_stream &out, const std::vector<std::string> &args) const {
	bool extended = !args.empty() && args[0] == "extended";

	return output_info(out, extended);
}

void pim_interface::address_added_or_removed(bool added, const inet6_addr &addr) {
	if (added) {
		if (addr.is_linklocal()) {
			if (intf_state != NOT_READY)
				return;

			if (!pim->pim_sock.join_mc(owner(), pim_all_routers)) {
				if (should_log(WARNING)) {
					log().perror("Failed to join All-PIM-"
						     "Routers multicast group");
				}
			}

			if (!start_timers()) {
				if (should_log(WARNING)) {
					log().writeline("Failed to start required timers");
				}
			}

			state was = intf_state;
			intf_state = owner()->globals().empty() ? LOCAL_READY : READY;

			if (should_log(DEBUG)) {
				if (was != intf_state) {
					if (intf_state == LOCAL_READY) {
						log().writeline("Has link-local address, changed to LOCAL_READY.");
					} else {
						log().writeline("Has global address, changed to READY.");
					}
				}
			}

			pim->interface_state_changed(this, NOT_READY);
		} else {
			if (intf_state == LOCAL_READY) {
				intf_state = READY;

				if (should_log(DEBUG))
					log().writeline("Has global address, changed to READY");

				pim->interface_state_changed(this, LOCAL_READY);
			}
		}
	} else {
		if (addr.is_linklocal()) {
			if (owner()->linklocals().empty()) {
				intf_state = NOT_READY;

				pim->pim_sock.leave_mc(owner(), pim_all_routers);

				if (should_log(DEBUG))
					log().writeline("Lost link-local, changed to NOT_READY");

				// stop hello timer

				pim->interface_state_changed(this, LOCAL_READY);
			}
		} else {
			if (owner()->globals().empty() && intf_state == READY) {
				intf_state = LOCAL_READY;
				if (should_log(DEBUG))
					log().writeline("Lost global address, changed to LOCAL_READY");
				pim->interface_state_changed(this, READY);
			}

			if (pim->my_address() == addr) {
				pim->check_my_address(true);
			}
		}
	}
}

bool pim_interface::send_local(sockaddr_in6 *dst, pim_message *msg, uint16_t len) const {
	sockaddr_in6 tmp = (*dst);
	tmp.sin6_scope_id = owner()->index();
	return pim->sendmsg(owner()->localaddr(), &tmp, msg, len);
}

bool pim_interface::send_all_routers(pim_message *msg, uint16_t len) const {
	return send_local(&pim_all_routers_addr, msg, len);
}

bool pim_interface::send_join_prune(pim_joinprune_message *msg) const {
	if (send_all_routers(msg, msg->length())) {
		m_stats.counter(JoinPruneCount, TX)++;
		return true;
	}

	return false;
}

bool pim_interface::send_assert(pim_assert_message *msg) const {
	if (send_all_routers(msg, sizeof(pim_assert_message))) {
		m_stats.counter(AssertCount, TX)++;
		return true;
	}

	return false;
}

bool pim_interface::start_timers() {
	hello_timer_id.start(true);

	return true;
}

void pim_interface::data_available(const sockaddr_in6 *src, const sockaddr_in6 *dst) {
	pim_message *pimmsg = g_mrd->ipktb->header<pim_message>();

	int len = g_mrd->ipktb->rlength;

	m_stats.counter(AllCount, RX)++;

	if (pimmsg->type() != pim_msg_register && should_log(MESSAGE_SIG)) {
		log().xprintf("%s message from %{addr} to %{addr} len %u\n",
			      pimmsg->type_name(), src->sin6_addr,
			      dst->sin6_addr, (uint32_t)len);
	}

	if (pimmsg->type() == pim_msg_register)
		len = sizeof(pim_register_message);

	if (!(pimmsg->has_valid_checksum(src->sin6_addr, dst->sin6_addr, len)
		|| (pimmsg->type() == pim_msg_register &&
		pimmsg->has_valid_checksum(src->sin6_addr, dst->sin6_addr, g_mrd->ipktb->rlength)))) {

		m_stats.counter(AllCount, Bad)++;

		if (should_log(MESSAGE_ERR)) {
			log().xprintf("Dropping message from %{addr} to %{addr}"
				      " len %u: Bad Checksum\n", src->sin6_addr,
				      dst->sin6_addr, (uint32_t)g_mrd->ipktb->rlength);
		}

		return;
	}

	if (dst->sin6_addr == pim_all_routers) {
		if ((int)src->sin6_scope_id != owner()->index()) {
			if (should_log(MESSAGE_ERR)) {
				log().xprintf("Dropping message from %{addr} to %{addr}"
					      " len %u: Wrong interface\n", src->sin6_addr,
					      dst->sin6_addr, (uint32_t)g_mrd->ipktb->rlength);
			}

			return;
		}

		switch (pimmsg->type()) {
		case pim_msg_hello:
			handle_hello(src, (pim_hello_message *)g_mrd->ipktb->pheader(), g_mrd->ipktb->rlength);
			break;
		case pim_msg_joinprune:
			handle_joinprune(src, (pim_joinprune_message *)g_mrd->ipktb->pheader(), g_mrd->ipktb->rlength);
			break;
		case pim_msg_assert:
			handle_assert(src, (pim_assert_message *)g_mrd->ipktb->pheader(), g_mrd->ipktb->rlength);
			break;
		case pim_msg_bootstrap:
			handle_bootstrap(src, dst, (pim_bootstrap_message *)g_mrd->ipktb->pheader(), g_mrd->ipktb->rlength);
			break;
		default:
			m_stats.counter(AllCount, Bad)++;
		}

	} else {
		switch (pimmsg->type()) {
		case pim_msg_register:
			handle_register(src, dst);
			break;
		case pim_msg_register_stop:
			handle_register_stop(src);
			break;
		case pim_msg_bootstrap:
			handle_bootstrap(src, dst, (pim_bootstrap_message *)g_mrd->ipktb->pheader(), g_mrd->ipktb->rlength);
			break;
		case pim_msg_candidate_rp_adv:
			handle_candidate_rp_adv(src,
				(pim_candidate_rp_adv_message *)g_mrd->ipktb->pheader(),
				g_mrd->ipktb->rlength);
			break;
		default:
			m_stats.counter(AllCount, Bad)++;
		}
	}
}

pim_neighbour *pim_interface::get_neighbour(const in6_addr &addr) const {
	for (neighbours_def::const_iterator i = neighbours.begin(); i != neighbours.end(); i++) {
		if ((*i)->has_address(addr))
			return *i;
	}
	return 0;
}

pim_neighbour *pim_interface::allocate_neighbour(const in6_addr &addr) {
	pim_neighbour *neigh = new pim_neighbour(this, addr);
	if (neigh)
		neighbours.push_back(neigh);

	return neigh;
}

void pim_interface::handle_hello(const sockaddr_in6 *from,
				 pim_hello_message *msg, uint16_t len) {
	m_stats.counter(HelloCount, RX)++;

	/* rejected by configuration */
	if (!conf()->neigh_acl_accepts(from->sin6_addr))
		return;

	uint16_t holdtime = 0;
	bool has_dr_priority = false;
	uint32_t dr_priority = 0;
	bool has_genid = false;
	uint32_t genid = mrd::get_randu32();
	bool has_lan_delay = false;
	uint16_t propdelay = 0, overrinter = 0;
	bool trackbit = false;

	int address_count = 0;
	pim_encoded_unicast_address *addresses = 0;
	int old_address_count = 0;
	pim_encoded_unicast_address *old_addresses = 0;

	int slen = sizeof(pim_hello_message);

	pim_hello_option *opt = msg->options();

	while (slen < len) {
		uint16_t optlen = ntoh(opt->length);

		switch (ntoh(opt->type)) {
		case pim_hello_option::holdtime:
			if (optlen == 2)
				holdtime = ntoh(opt->data16()[0]);
			break;
		case pim_hello_option::lan_prune_delay:
			if (optlen == 4) {
				has_lan_delay = true;
				propdelay = ntoh(opt->data16()[0]);
				overrinter = ntoh(opt->data16()[1]);
				trackbit = (propdelay & 0x8000) != 0;
				propdelay &= 0x7fff;
			}
			break;
		case pim_hello_option::dr_priority:
			if (optlen == 4) {
				has_dr_priority = true;
				dr_priority = ntoh(opt->data32()[0]);
			}
			break;
		case pim_hello_option::genid:
			if (optlen == 4) {
				has_genid = true;
				genid = ntoh(opt->data32()[0]);
			}
			break;
		case pim_hello_option::addrlist:
			if ((optlen % sizeof(pim_encoded_unicast_address)) == 0) {
				address_count = optlen / sizeof(pim_encoded_unicast_address);
				addresses = (pim_encoded_unicast_address *)opt->data();
			}
			break;
		case pim_hello_option::cisco_old_addrlist:
			if ((optlen % sizeof(pim_encoded_unicast_address)) == 0) {
				old_address_count = optlen / sizeof(pim_encoded_unicast_address);
				old_addresses = (pim_encoded_unicast_address *)opt->data();
			}
			break;
		}

		slen += sizeof(pim_hello_option) + optlen;
		opt = opt->next();
	}

	pim_neighbour *neigh;

	if ((neigh = get_neighbour(from->sin6_addr))) {
		if (holdtime == 0) {
			neighbour_timed_out(neigh);
			return;
		}

		if (!neigh->compare_genid(genid)) {
			if (should_log(NORMAL))
				neigh->log().writeline("Had different GenID, forcing timeout.");
			remove_neighbour(neigh, false);
			neigh = 0;
		}
	}

	bool is_new = false;

	if (!neigh) {
		if (!(neigh = allocate_neighbour(from->sin6_addr))) {
			if (should_log(DEBUG))
				log().writeline("Failed to allocate neighbor state.");
			return;
		}

		is_new = true;
	}

	if (!conf()->support_old_cisco_addrlist()) {
		old_addresses = 0;
		old_address_count = 0;
	}

	neigh->update_from_hello(addresses, address_count,
				 old_addresses, old_address_count, holdtime);

	if (has_dr_priority)
		neigh->set_dr_priority(dr_priority);
	if (has_genid)
		neigh->set_genid(genid);
	if (has_lan_delay)
		neigh->set_lan_delay(propdelay, overrinter, trackbit);

	if (is_new)
		found_new_neighbour(neigh);

	check_lan_delay();
	elect_subnet_dr();
}

void pim_interface::handle_joinprune(const sockaddr_in6 *_from, pim_joinprune_message *msg, uint16_t len) {
	m_stats.counter(JoinPruneCount, RX)++;

	/* Just to be sure */
	if (g_mrd->has_address(_from->sin6_addr))
		return;

	if (should_log(MESSAGE_CONTENT)) {
		base_stream &os = log();
		os.inc_level();
		_debug_pim_dump(os, *msg);
		os.dec_level();
	}

	inet6_addr upneigh(msg->upstream_neigh.addr);

	if (!g_mrd->has_address(upneigh)) {
		/* Lets monitor the Join/Prunes in the link
		 * to react properly */

		handle_external_joinprune(_from, msg, len);

		return;
	}

	pim_neighbour *neigh = pim->get_neighbour(_from->sin6_addr);
	if (!neigh) {
		if (should_log(DEBUG)) {
			log().xprintf("Dropping Join/Prune from %{addr}, not "
				      "a known neighbor.\n", _from->sin6_addr);
		}

		m_stats.counter(JoinPruneCount, Bad)++;

		return;
	}

	pim_group_node *node;

	pim_joinprune_group *grp = msg->groups();

	for (uint8_t i = 0; i < msg->ngroups; i++, grp = grp->next()) {
		inet6_addr groupaddr(grp->maddr.addr, grp->maddr.masklen);

		groupconf *entry = g_mrd->match_group_configuration(groupaddr);
		pim_groupconf_node *info = entry ? (pim_groupconf_node *)entry->get_child("pim") : 0;

		for (pim_jp_g_iterator i = grp->join_begin();
					i != grp->join_end(); ++i) {
			if (i->wc() && i->rpt()) {
				bool accept_rp = true;

				if (info)
					accept_rp = info->get_property_address
							("accept_rp").matches(i->address());

				if (accept_rp) {
					address_set prunes;
					grp->pruned_addrs(prunes);

					handle_join_wc_rpt(groupaddr, i->address(),
							   prunes, msg->holdtime(),
							   i->rpt());
				} else {
					/// 3.2.2.1.1
				}
			} else if (!i->wc() && !i->rpt()) {
				handle_join_source(groupaddr, i->address(),
						   msg->holdtime(), i->rpt());
			} else {
				handle_join(groupaddr, i->address(),
					    msg->holdtime(), i->rpt());
			}
		}

		for (pim_jp_g_iterator i = grp->prune_begin();
					i != grp->prune_end(); ++i) {
			/* we update the node reference on each cycle as
			 * it may have been deleted due to a prune */
			node = pim->get_group(groupaddr);
			if (node == NULL)
				continue;

			pim_source_state_base *target = NULL;
			uint32_t holdtime = 0;

			if (!i->wc()) {
				target = node->get_state(i->address(), i->rpt());
				holdtime = msg->holdtime();
			} else if (i->wc() && i->rpt()) {
				if (node->rpaddr() == i->address())
					target = node->wildcard();
			}

			if (target)
				target->set_oif(owner(), holdtime, false);
		}
	}
}

void pim_interface::handle_external_joinprune(const sockaddr_in6 *_from,
					      pim_joinprune_message *msg,
					      uint16_t len) {
	pim_group_node *node;

	pim_neighbour *upneigh = pim->get_neighbour(msg->upstream_neigh.addr);
	if (!upneigh)
		return;

	pim_joinprune_group *grp = msg->groups();

	for (uint8_t i = 0; i < msg->ngroups; i++, grp = grp->next()) {
		inet6_addr groupaddr(grp->maddr.addr, grp->maddr.masklen);

		node = pim->get_group(groupaddr);
		if (!node)
			continue;

		for (pim_jp_g_iterator i = grp->join_begin();
					i != grp->join_end(); ++i) {
			if (i->wc() || i->rpt())
				continue;

			pim_group_source_state *state = node->get_state(i->address());
			if (state == NULL)
				continue;

			if (state->upstream_neighbour() != upneigh)
				continue;

			pim_neighbour::upstream_path *path = state->upstream_path();
			if (path == NULL)
				continue;

			/* A (S,G) that is being currenty joined */

			/* If (S,G) is joined and we see a Join, supress our
			 * next one, if sent in the following `override` milisecs */
			if (path->is_joined())
				path->update_last_seen(msg->holdtime());
		}

		for (pim_jp_g_iterator i = grp->prune_begin();
					i != grp->prune_end(); ++i) {
			if (i->wc() || i->rpt())
				continue;

			pim_group_source_state *state = node->get_state(i->address());
			if (state == NULL)
				continue;

			if (state->upstream_neighbour() == upneigh &&
			    state->upstream_path()) {
				/* A (S,G) that is being currenty pruned */

				/* If (S,G) is joined and we see a Prune,
				 * trigger a Join message upstream */
				if (state->upstream_path()->is_joined())
					state->upstream_path()->refresh_now();
			}
		}
	}

}

struct create_group_pim_intf_context : mrd::create_group_context {
	create_group_pim_intf_context();

	bool from_join;

	address_set prunedaddrs;
	uint32_t holdtime;
	bool rpt, wc;

	uint8_t *pktbuf;
	uint16_t pktlen;
	bool nullreg;
};

create_group_pim_intf_context::create_group_pim_intf_context() {
	from_join = true;
	holdtime = 0;
	rpt = wc = false;
	pktbuf = 0;
	pktlen = 0;
	nullreg = false;
}

void pim_interface::handle_join_wc_rpt(const inet6_addr &grpaddr,
		const inet6_addr &src, const address_set &pruneaddrs,
		uint16_t ht, bool rpt) {

	group *grp = g_mrd->get_group_by_addr(grpaddr);

	uint32_t holdtime = ht * 1000;

	if (grp)
		handle_join_wc_rpt(grp, src, pruneaddrs, holdtime, rpt);
	else {
		create_group_pim_intf_context *ctx = new create_group_pim_intf_context;

		if (!ctx)
			return;

		ctx->from_join = true;

		ctx->groupaddr = grpaddr;
		ctx->requester = src;

		ctx->prunedaddrs = pruneaddrs;
		ctx->holdtime = holdtime;
		ctx->rpt = rpt;
		ctx->wc = true;

		g_mrd->create_group(pim, this, ctx);
	}
}

void pim_interface::event(int type, void *ptr) {
	if (type != mrd::CreatedGroup) {
		interface_node::event(type, ptr);
		return;
	}

	create_group_pim_intf_context *ctx = (create_group_pim_intf_context *)ptr;

	if (ctx->from_join) {
		if (ctx->wc) {
			handle_join_wc_rpt(ctx->result, ctx->requester,
					   ctx->prunedaddrs, ctx->holdtime,
					   ctx->rpt);
		} else {
			handle_join_source(ctx->result, ctx->requester,
					   ctx->holdtime, ctx->rpt);
		}
	} else {
		pim_group_node *node = (pim_group_node *)ctx->result->node_owned_by(pim);
		if (node) {
			node->do_register(ctx->requester.address_p(),
					  (ip6_hdr *)ctx->pktbuf, ctx->pktlen,
					  ctx->nullreg);
		}

		delete ctx->pktbuf;
	}

	delete ctx;
}

void pim_interface::handle_join_wc_rpt(group *grp, const inet6_addr &src,
		const address_set &pruneaddrs, uint32_t holdtime, bool rpt) {
	if (!grp)
		return;

	pim_group_node *node = (pim_group_node *)grp->node_owned_by(pim);

	/// 3.2.2.1.2
	if (!node) {
		/* Either PIM is disabled for this group or we didn't have
		 * enough memory in the past */
		return;
	}

	if (node->has_rp() && !(node->rpaddr() == src)) {
		/*
		 * We already have a group instance for G, and the currently
		 * used RP address differs from the requested one, ignore Join.
		 */
		return;
	}

	bool had = node->has_wildcard();

	if (!had) {
		if (!node->create_wildcard()) {
			return;
		}
	}

	node->wildcard()->set_oif(owner(), holdtime);

	if (!had) {
		rp_source rpsrc;
		inet6_addr possiblerp = node->rp_for_group(rpsrc);
		if (!(possiblerp == src)) {
			if (should_log(DEBUG)) {
				log().writeline("RP in J/P message is not the"
						"configured one, ignoring Join/Prune.");
				return;
			}
		}

		node->set_rp(src, rps_join);

		/// 3.2.2.1.5
		node->wildcard()->check_upstream_path();
	}

	handle_join(node, src, holdtime, rpt);
}

void pim_interface::handle_join_source(const inet6_addr &grpaddr, const inet6_addr &src, uint32_t holdtime, bool rpt) {
	group *grp = g_mrd->get_group_by_addr(grpaddr);

	if (grp)
		handle_join_source(grp, src, holdtime, rpt);
	else {
		create_group_pim_intf_context *ctx = new create_group_pim_intf_context;

		if (!ctx)
			return;

		ctx->from_join = true;

		ctx->groupaddr = grpaddr;
		ctx->requester = src;

		ctx->holdtime = holdtime;
		ctx->rpt = rpt;
		ctx->wc = false;

		g_mrd->create_group(pim, this, ctx);
	}
}

void pim_interface::handle_join_source(group *grp, const inet6_addr &src, uint32_t holdtime, bool rpt) {
	if (!grp)
		return;

	pim_group_node *node = (pim_group_node *)grp->node_owned_by(pim);

	if (!node)
		return;

	pim_source_state_base *state = node->get_state(src, rpt);

	if (!state) {
		/// 3.2.2.2

		/* If we don't have a state for G, as it is a join, downstream
		 * wanted to revert Prune to Join, which doesnt make sense here. */
		if (rpt)
			return;

		node->create_state(src, rpt, owner(), false, holdtime);

//		if (pimrouter->mrib().rpf_check(node, src, owner()))
//			node->create_state(src, owner(), false, holdtime);
//		else
//			g_mrd->log().debug() << "Downstream Join failed: RPF check failed." << endl;
	}

	handle_join(node, src, holdtime, rpt);
}

void pim_interface::handle_join(const inet6_addr &grpaddr, const inet6_addr &src, uint32_t holdtime, bool rpt) {
	group *grp = g_mrd->get_group_by_addr(grpaddr);
	if (!grp)
		return;

	pim_group_node *node = (pim_group_node *)grp->node_owned_by(pim);

	if (node)
		handle_join(node, src, holdtime, rpt);
}

void pim_interface::handle_join(pim_group_node *node, const inet6_addr &src, uint32_t holdtime, bool rpt) {
	pim_source_state_base *state = node->get_state(src, rpt);
	if (state)
		state->set_oif(owner(), holdtime);
}

void pim_interface::handle_bootstrap(const sockaddr_in6 *src, const sockaddr_in6 *dst,
					pim_bootstrap_message *msg, uint16_t length) {
	m_stats.counter(BootstrapCount, RX)++;

#ifndef PIM_NO_BSR
	pim->bsr().handle_bootstrap_message(this, src, dst, msg, length);
#endif
}

void pim_interface::handle_assert(const sockaddr_in6 *from, pim_assert_message *msg, uint16_t length) {
	m_stats.counter(AssertCount, RX)++;

	if (should_log(MESSAGE_CONTENT)) {
		base_stream &os = log();
		os.inc_level();
		_debug_pim_dump(os, *msg);
		os.dec_level();
	}

	if (!get_neighbour(from->sin6_addr)) {
		m_stats.counter(AssertCount, Bad)++;
		return;
	}

	inet6_addr grpaddr(msg->gaddr.addr, msg->gaddr.masklen);
	pim_group_node *node = pim->get_group(grpaddr);

	bool rpt = msg->rpt();
	uint32_t metric_pref = msg->metric_pref();
	uint32_t metric = ntoh(msg->metric);

	if (node) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&msg->saddr.addr)) {
			pim_group_source_state *state = node->get_state(msg->saddr.addr);
			if (state) {
				pim_common_oif::assert_state prev = pim_common_oif::AssertNoInfo;
				bool existed = false;

				pim_common_oif *oif = (pim_common_oif *)state->get_oif(owner());
				if (oif) {
					prev = oif->current_assert_state();
					existed = true;
				}

				state->handle_assert(owner(), from->sin6_addr,
						     rpt, metric, metric_pref);

				/* for some future reason the oif may be released meanwhile */
				oif = (pim_common_oif *)state->get_oif(owner());

				if (!oif && existed) {
					/* transitioned somehow */
					return;
				}

				pim_common_oif::assert_state current = oif ?
					oif->current_assert_state() : pim_common_oif::AssertNoInfo;

				if (current != pim_common_oif::AssertNoInfo || current != prev) {
					/* (S,G) Assert state machine is not NoInfo
					 * or a transition occurred: no (*,G) handling */
					return;
				}
			}
		}

		if (node->has_wildcard()) {
			node->wildcard()->handle_assert(owner(), from->sin6_addr,
						        rpt, metric, metric_pref);
		}
	}
}

void pim_interface::handle_register(const sockaddr_in6 *src, const sockaddr_in6 *dst) {
	m_stats.counter(RegisterCount, RX)++;

	if (!g_mrd->has_address(dst->sin6_addr)) {
		m_stats.counter(RegisterCount, Bad)++;
		return;
	}

	pim_register_message *msg = g_mrd->ipktb->header<pim_register_message>();

	ip6_hdr *pktbuf = msg->ip6_header();
	uint16_t pktlen = g_mrd->ipktb->rlength - sizeof(pim_register_message);

	if (pktbuf->ip6_src == in6addr_any) {
		m_stats.counter(RegisterCount, Bad)++;
		return;
	}

	/* Reached Hop Limit */
	if (pktbuf->ip6_hlim <= 1) {
		/* XXX send register-stop? */
		return;
	}

	pim_group_node *node = pim->get_group(pktbuf->ip6_dst);
	if (node) {
		node->do_register(&src->sin6_addr, pktbuf, pktlen, msg->null());
	} else {
		/* XXX if SSM don't create group */

		create_group_pim_intf_context *ctx = new create_group_pim_intf_context;

		if (!ctx)
			return;

		ctx->from_join = false;

		ctx->groupaddr = pktbuf->ip6_dst;
		ctx->requester = src->sin6_addr;

		ctx->pktlen = pktlen;
		ctx->pktbuf = new uint8_t[pktlen];
		if (!ctx->pktbuf) {
			/* XXX drop */
			delete ctx;
			return;
		}

		ctx->nullreg = msg->null();

		memcpy(ctx->pktbuf, pktbuf, pktlen);

		g_mrd->create_group(pim, this, ctx);
	}
}

void pim_interface::handle_register_stop(const sockaddr_in6 *src) {
	m_stats.counter(RegisterStopCount, RX)++;

	pim_register_stop_message *msg = g_mrd->ipktb->header<pim_register_stop_message>();

	pim_group_node *node = pim->get_group(msg->gaddr.addr);
	if (node)
		node->register_stop(src->sin6_addr, msg->uaddr.addr);
}

void pim_interface::handle_candidate_rp_adv(const sockaddr_in6 *from,
			pim_candidate_rp_adv_message *msg, uint16_t len) {
	m_stats.counter(CandRPCount, RX)++;

#ifndef PIM_NO_BSR
	pim->bsr().handle_candidate_rp_adv(this, from, msg, len);
#endif
}

void pim_interface::neighbour_timed_out(pim_neighbour * &neigh) {
	if (should_log(NORMAL))
		neigh->log().writeline("Timed out.");

	remove_neighbour(neigh, true);
}

void pim_interface::remove_neighbour(pim_neighbour *neigh, bool elect) {
	for (neighbours_def::iterator i = neighbours.begin(); i != neighbours.end(); i++) {
		if (*i == neigh) {
			neighbours.erase(i);

			if (elect) {
				check_lan_delay();
				elect_subnet_dr();
			}

			neigh->set_present(false);

			pim->lost_neighbour(neigh);
			neigh->shutdown();
			delete neigh;

			return;
		}
	}
}

void pim_interface::check_lan_delay() {
	m_landelay_enabled = true;

	for (neighbours_def::const_iterator i = neighbours.begin();
			m_landelay_enabled && i != neighbours.end(); ++i)
		m_landelay_enabled = (*i)->has_lan_delay();

	if (m_landelay_enabled) {
		m_propagation_delay = conf()->propagation_delay();
		m_override_interval = conf()->override_interval();

		for (neighbours_def::const_iterator i = neighbours.begin(); i != neighbours.end(); ++i) {
			if ((*i)->propagation_delay() > m_propagation_delay)
				m_propagation_delay = (*i)->propagation_delay();
			if ((*i)->override_interval() > m_override_interval)
				m_override_interval = (*i)->override_interval();
		}
	} else {
		m_propagation_delay = conf()->propagation_delay();
		m_override_interval = conf()->override_interval();
	}
}

bool pim_interface::suppression_enabled() const {
	if (!lan_delay_enabled())
		return true;

	for (neighbours_def::const_iterator i = neighbours.begin(); i != neighbours.end(); ++i) {
		if (!(*i)->tracking_support())
			return true;
	}

	return false;
}

uint32_t pim_interface::suppressed_value() const {
	if (!suppression_enabled())
		return 0;

	uint32_t a = (uint32_t)(conf()->joinprune_interval() * 1.1);
	uint32_t b = (uint32_t)(conf()->joinprune_interval() * 1.4);

	return a + mrd::get_randu32() % (b-a);
}

void pim_interface::elect_subnet_dr() {
	bool mayuseprio = true;

	for (neighbours_def::const_iterator i = neighbours.begin(); mayuseprio && i != neighbours.end(); ++i)
		mayuseprio = (*i)->has_dr_priority();

	pim_neighbour *bestneigh = 0;

	// elect DR between known neighbours
	if (!neighbours.empty()) {
		bestneigh = *neighbours.begin();

		neighbours_def::const_iterator i = neighbours.begin();
		i++;

		for (; i != neighbours.end(); i++) {
			if (!mayuseprio || (bestneigh->dr_priority() == (*i)->dr_priority())) {
				if (bestneigh->localaddr() < (*i)->localaddr()) {
					bestneigh = *i;
				}
			} else if (bestneigh->dr_priority() < (*i)->dr_priority()) {
				bestneigh = *i;
			}
		}
	}

	// match the elected neighbour against us
	if (bestneigh) {
		uint32_t my_dr_prio = conf()->dr_priority();

		if (!mayuseprio || (my_dr_prio == bestneigh->dr_priority())) {
			if (bestneigh->localaddr() < inet6_addr(*owner()->linklocal()))
				bestneigh = 0;
		} else {
			if (my_dr_prio > bestneigh->dr_priority())
				bestneigh = 0;
		}
	}

	/* We must set elected_dr before calling dr_changed */
	pim_neighbour *old = elected_dr;

	elected_dr = bestneigh;

	if (old != bestneigh) {
		if (bestneigh && !old) {
			if (should_log(NORMAL))
				log().xprintf("No longer the DR, new DR is %{Addr}\n", bestneigh->localaddr());
			pim->dr_changed(this, false);
		} else if (old && !bestneigh) {
			if (should_log(NORMAL))
				log().writeline("Im now the DR");
			pim->dr_changed(this, true);
		} else if (bestneigh) {
			if (should_log(NORMAL))
				log().xprintf("New DR is %{Addr}\n", bestneigh->localaddr());
		}
	}
}

void pim_interface::found_new_neighbour(pim_neighbour *neigh) {
	if (should_log(NORMAL))
		log().xprintf("New Neighbour at %{Addr}\n", neigh->localaddr());

	send_hello();

#ifndef PIM_NO_BSR
	if (am_dr()) {
		pim->bsr().found_new_neighbour(neigh);
	}
#endif

	pim->found_new_neighbour(neigh);
}

void pim_interface::send_hello() {
	send_hellox(conf()->holdtime() / 1000);
}

static inline void _hello_advance_option(int &optlen, pim_hello_option * &opt, int length) {
	optlen += sizeof(pim_hello_option) + length;
	opt = opt->next();
}

static void _build_addrlist(int optid, pim_hello_option * &opt,
			    const std::set<inet6_addr> &addrs, int &optlen) {
	opt->construct(optid, addrs.size() * sizeof(pim_encoded_unicast_address));

	pim_encoded_unicast_address *addr = (pim_encoded_unicast_address *)opt->data();
	for (std::set<inet6_addr>::const_iterator i = addrs.begin(); i != addrs.end(); i++, addr++) {
		addr->construct(*i);
	}

	_hello_advance_option(optlen, opt, addrs.size() * sizeof(pim_encoded_unicast_address));
}

void pim_interface::send_hellox(uint16_t holdtime) {
	pim_hello_message *hellomsg = g_mrd->opktb->header<pim_hello_message>();

	hellomsg->construct();

	pim_hello_option *opt = hellomsg->options();

	int optlen = 0;

	opt->add_uint16(pim_hello_option::holdtime, holdtime);
	_hello_advance_option(optlen, opt, 2);

	if (owner()->is_multiaccess()) {
		opt->add_uint16pair(pim_hello_option::lan_prune_delay,
				    conf()->propagation_delay(),
				    conf()->override_interval());

		_hello_advance_option(optlen, opt, 4);
	}

	opt->add_uint32(pim_hello_option::genid, gen_id);
	_hello_advance_option(optlen, opt, 4);

	opt->add_uint32(pim_hello_option::dr_priority, conf()->dr_priority());
	_hello_advance_option(optlen, opt, 4);

	const std::set<inet6_addr> &addrs = owner()->globals();
	if (!addrs.empty()) {
		_build_addrlist(pim_hello_option::addrlist, opt, addrs, optlen);
		if (conf()->support_old_cisco_addrlist())
			_build_addrlist(pim_hello_option::cisco_old_addrlist, opt, addrs, optlen);
	}

	if (should_log(MESSAGE_SIG))
		log().xprintf("Hello message to All-Routers, holdtime = %u.\n",
			      (uint32_t)holdtime);

	if (send_all_routers(hellomsg, sizeof(pim_hello_message) + optlen)) {
		m_stats.counter(HelloCount, TX)++;
	}
}

bool pim_interface::call_method(int id, base_stream &out,
				const std::vector<std::string> &args) {
	switch (id) {
	case pim_intf_method_flap:
		return flap_neighbour(out, args, false);
	case pim_intf_method_force_timeout:
		return flap_neighbour(out, args, true);
	}

	return interface_node::call_method(id, out, args);
}

bool pim_interface::flap_neighbour(base_stream &out,
				   const std::vector<std::string> &args,
				   bool remove) {
	if (args.empty())
		return false;

	inet6_addr addr;
	if (!addr.set(args[0]))
		return false;

	pim_neighbour *neigh = 0;
	neighbours_def::iterator i;

	for (i = neighbours.begin(); i != neighbours.end(); i++) {
		if ((*i)->has_address(addr)) {
			neigh = *i;
			break;
		}
	}

	if (!neigh) {
		out.writeline("No such neighbour.");
	} else {
		if (remove) {
			neighbour_timed_out(neigh);
		} else {
			neighbours.erase(i);
			pim->lost_neighbour(neigh);
			neighbours.push_back(neigh);
			pim->found_new_neighbour(neigh);
		}
	}

	return true;
}

void pim_interface::property_changed(node *n, const char *name) {
	if (!strcmp(name, "dr_priority")) {
		if (conf()) {
			if (should_log(DEBUG))
				log().xprintf("Changed DR-Priority to %u\n",
					      (uint32_t)conf()->dr_priority());

			send_hello();
			elect_subnet_dr();
		}
	} else if (!strcmp(name, "hello_interval")) {
		update_hello_interval(conf()->hello_interval());
	}
}

void pim_interface::update_hello_interval(uint32_t value) {
	if (value == 0) {
		if (hello_timer_id.is_running() && should_log(DEBUG))
			log().writeline("Hello Interval set to 0, entering Passive mode.");

		hello_timer_id.stop();
	} else if (intf_state >= LOCAL_READY) {
		hello_timer_id.start_or_update(value, true);
	} else {
		hello_timer_id.update(value, true);
	}
}

uint32_t pim_interface::effective_propagation_delay() const {
	return m_propagation_delay;
}

uint32_t pim_interface::effective_override_interval() const {
	return m_override_interval;
}

bool pim_interface::lan_delay_enabled() const {
	return m_landelay_enabled;
}


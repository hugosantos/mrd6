/*
 * Multicast Routing Daemon (MRD)
 *   pim_router.cpp
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

#include <mrdpriv/pim/router.h>
#include <mrdpriv/pim/interface.h>
#include <mrdpriv/pim/group.h>
#include <mrdpriv/pim/neighbour.h>
#include <mrdpriv/pim/def.h>

#include <mrd/mrd.h>
#include <mrd/rib.h>
#include <mrd/mrib.h>

#include <unistd.h>
#include <errno.h>

#include <cstdlib>
#include <cmath>

in6_addr pim_all_routers;
sockaddr_in6 pim_all_routers_addr;
pim_router *pim = 0;

enum {
	pim_router_method_rpf	= 9000,
	pim_router_method_group_rp,
	pim_router_method_group_summary,
};

static const method_info pim_router_methods[] = {
	{ "rpf-neighbor", "Displays RPF neighbor information",
		pim_router_method_rpf, true, 0 },
	{ "group-rp", "Displays the would-be RP for the specific group",
		pim_router_method_group_rp, true, 0 },
	{ "group-summary", "Displays a summary of active PIM group state",
		pim_router_method_group_summary, true, 0 },
	{ 0 }
};

pim_router::pim_router()
	: router("pim"), pim_sock("pim", this,
		std::mem_fun(&pim_router::data_available)),
	  m_gc("pim garbage collector", this,
		std::mem_fun(&pim_router::handle_garbage_collector), 5000, true)
#ifndef PIM_NO_BSR
	  , m_bsr(this)
#endif
	{

	pim_all_routers = inet6_addr("ff02::d").address();

	memset(&pim_all_routers_addr, 0, sizeof(pim_all_routers_addr));

	pim_all_routers_addr.sin6_family = AF_INET6;
	pim_all_routers_addr.sin6_addr = pim_all_routers;
}

pim_router::~pim_router() {
}

const char *pim_router::description() const {
	return "Protocol Independent Multicast (PIM) Routing Protocol";
}

bool pim_router::output_info(base_stream &ctx, const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	ctx.writeline("PIM");

	ctx.inc_level();

#ifndef PIM_NO_BSR
	m_bsr.output_info(ctx);
#endif

	ctx.dec_level();

	return true;
}

bool pim_router::check_startup() {
	if (!router::check_startup())
		return false;

	if (m_properties.size() < 1)
		return false;

#ifndef PIM_NO_BSR
	if (!bsr().check_startup())
		return false;
#endif

	if (!g_mrd->register_source_sink(this, true))
		return false;

	import_methods(pim_router_methods);

	m_gc.start();

	int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_PIM);
	if (sock < 0) {
		g_mrd->log().perror("PIM: failed to create PIM socket");
		return false;
	}

	if (!pim_sock.register_fd(sock)) {
		close(sock);
		return false;
	}

	if (!pim_sock.enable_mc_loop(false))
		return false;

	pim_sock.set_mcast_hoplimit(1);

	return true;
}

base_stream &pim_router::log_router_desc(base_stream &os) const {
	return os.write("PIM, ");
}

bool pim_router::call_method(int id, base_stream &out,
			     const std::vector<std::string> &args) {
	if (id == pim_router_method_rpf) {
		if (args.size() != 1)
			return false;

		inet6_addr addr;
		if (!addr.set(args[0].c_str()))
			return false;

		pim_neighbour *neigh = get_rpf_neighbour(addr);

		if (neigh) {
			neigh->output_info(out, false);
		} else {
			out.writeline("No RPF neighbor.");
		}

		return true;
	} else if (id == pim_router_method_group_rp) {
		if (args.size() != 1)
			return false;

		inet6_addr addr;
		if (!addr.set(args[0].c_str()))
			return false;

		pim_groupconf_node *pconf = 0;
		groupconf *conf = g_mrd->match_group_configuration(addr);
		while (conf && !pconf) {
			pconf = (pim_groupconf_node *)conf->get_child("pim");
			conf = g_mrd->get_similiar_groupconf_node(conf);
		}

		if (!pconf) {
			out.writeline("No available configuration.");
			return true;
		}

		in6_addr rpaddr;
		rp_source src;
		if (pconf->rp_for_group(addr, rpaddr, src)) {
			out.xprintf("RP: %{addr} [", rpaddr);
			if (src == rps_static)
				out.write("static");
			else if (src == rps_embedded)
				out.write("embedded");
			else if (src == rps_rp_set)
				out.write("rp_set");
			else
				out.write("unknown");
			out.writeline("]");
		} else {
			out.writeline("No available RP");
		}

		return true;
	} else if (id == pim_router_method_group_summary) {
		if (args.size() > 1)
			return false;

		inet6_addr mask;
		if (!args.empty()) {
			if (!mask.set(args[0].c_str()))
				return false;
		}

		mrd::group_list::const_iterator i = g_mrd->group_table().begin();

		for (; i != g_mrd->group_table().end(); ++i) {
			if (!mask.matches(i->first))
				continue;

			pim_group_node *grp =
				(pim_group_node *)i->second->node_owned_by(this);
			if (!grp)
				continue;

			out.xprintf("%{Addr}\n", i->first);
			out.inc_level();

			if (grp->wildcard()) {
				out.xprintf("Wildcard present, RP is at %{addr}\n", grp->rpaddr());
			}

			int count = grp->source_state_set().size();

			out.xprintf("Has %i state%s.\n", count, count > 1 ? "s" : "");

			int local = grp->local_source_state_set().size();

			if (local > 0) {
				out.xprintf("Of which %i %s local.\n", local, local > 1 ? "are" : "is");
			}

			out.dec_level();
		}

		return true;
	}

	return router::call_method(id, out, args);
}

void pim_router::check_my_address(bool force) {
	if (!force && !m_my_address.is_any())
		return;

	inet6_addr was = m_my_address;

	m_my_address = in6addr_any;

	const mrd::interface_list &intflist = g_mrd->intflist();

	for (mrd::interface_list::const_iterator i = intflist.begin();
						i != intflist.end(); ++i) {
		if (!i->second->up())
			continue;

		const std::set<inet6_addr> &globals = i->second->globals();
		for (std::set<inet6_addr>::const_iterator j = globals.begin();
							j != globals.end(); ++j) {
			if (m_my_address.is_any() || *j < m_my_address)
				m_my_address = *j;
		}
	}

	if (!(was == m_my_address)) {
		if (!m_my_address.is_any()) {
			if (should_log(DEBUG))
				log().xprintf("Primary global address is"
					      " %{Addr}.\n", m_my_address);

#ifndef PIM_NO_BSR
			if (was.is_any())
				bsr().acquired_primary_address();
#endif
		} else if (!was.is_any()) {
			if (should_log(DEBUG))
				log().writeline("Lost primary global address.");
		}
	}
}

void pim_router::shutdown() {
	if (should_log(DEBUG))
		log().writeline("Shutdown");

	g_mrd->register_source_sink(this, false);

#ifndef PIM_NO_BSR
	bsr().leaving();
#endif

	mrd::group_list::const_iterator j;

	for (j = g_mrd->group_table().begin();
		j != g_mrd->group_table().end(); ++j) {
		group_node *node = j->second->node_owned_by(this);
		if (node) {
			release_group((pim_group_node *)node);
		}

	}

	const mrd::interface_list &intflist = g_mrd->intflist();

	for (mrd::interface_list::const_iterator i = intflist.begin();
						i != intflist.end(); ++i) {
		pim_interface *intf = (pim_interface *)i->second->node_owned_by(this);
		if (intf) {
			intf->shutdown();
			delete intf;
		}
	}

#ifndef PIM_NO_BSR
	bsr().shutdown();
#endif

	pim_sock.unregister();

	router::shutdown();
}

void pim_router::handle_garbage_collector() {
	mrd::group_list::const_iterator i = g_mrd->group_table().begin();

	while (i != g_mrd->group_table().end()) {
		group_node *node = i->second->node_owned_by(this);
		++i;
		if (node)
			((pim_group_node *)node)->garbage_collect();
	}
}

void pim_router::interface_state_changed(pim_interface *intf, pim_interface::state) {
	switch (intf->get_state()) {
	case pim_interface::READY:
		check_my_address(false);
		break;
	default:
		break;
	}
}

void pim_router::created_group(group *grp) {
	pim_groupconf_node *ent =
		(pim_groupconf_node *)grp->conf()->create_child("pim");

	if (!ent)
		return;

	pim_group_node *node = create_group(grp->id(), grp->conf());
	if (node) {
		node->set_rp();
		if (!node->attach(grp, ent)) {
			if (should_log(WARNING)) {
				log().xprintf("Failed to attach pim node to "
					      "group %{Addr}\n", grp->id());
			}
		}
	} else if (should_log(WARNING)) {
		log().xprintf("Failed to attach pim node to group %{Addr}\n", grp->id());
	}
}

void pim_router::released_group(group *grp) {
	release_group((pim_group_node *)grp->node_owned_by(this));
}

void pim_router::release_group(pim_group_node *node) {
	if (!node)
		return;

	if (node->owner()->node_owned_by(this) != node)
		return;

	node->owner()->dettach_node(node);
	delete node;
}

void pim_router::add_interface(interface *intf) {
	if (!intf->conf()->create_child("pim"))
		return;

	pim_interface *pimintf = new pim_interface();
	if (!pimintf || !pimintf->check_startup()) {
		delete pimintf;
		return;
	}

	if (!intf->attach_node(pimintf)) {
		pimintf->shutdown();
		delete pimintf;
	}
}

void pim_router::remove_interface(interface *intf) {
	pim_interface *pimintf = (pim_interface *)intf->node_owned_by(this);
	if (!pimintf) {
		return;
	}

	pimintf->shutdown();
	delete pimintf;

	if (intf->globals().find(m_my_address) != intf->globals().end()) {
		check_my_address(true);
	}
}

intfconf_node *pim_router::create_interface_configuration(intfconf *conf) {
	return new pim_intfconf_node(conf);
}

groupconf_node *pim_router::create_group_configuration(groupconf *conf) {
	return new pim_groupconf_node(conf);
}

pim_interface *pim_router::get_interface(interface *intf) const {
	if (!intf)
		return 0;
	return (pim_interface *)intf->node_owned_by(this);
}

pim_interface *pim_router::get_interface(int dev) const {
	return get_interface(g_mrd->get_interface_by_index(dev));
}

pim_group_node *pim_router::create_group(const inet6_addr &addr, node *conf) {
	pim_group_node *node = get_group(addr);
	if (!node) {
		return new pim_group_node(this, addr,
				(pim_groupconf_node *)conf->get_or_create_child("pim"));
	}
	return node;
}

pim_group_node *pim_router::get_group(const inet6_addr &addr) const {
	group *grp = g_mrd->get_group_by_addr(addr);
	if (grp)
		return (pim_group_node *)grp->node_owned_by(this);
	return 0;
}

void pim_router::found_new_neighbour(pim_neighbour *neigh) const {
	mrd::group_list::const_iterator j = g_mrd->group_table().begin();

	for (; j != g_mrd->group_table().end(); ++j) {
		group_node *node = j->second->node_owned_by(this);
		if (node) {
			((pim_group_node *)node)->found_new_neighbour(neigh);
		}
	}
}

void pim_router::lost_neighbour(pim_neighbour *neigh) const {
	mrd::group_list::const_iterator j = g_mrd->group_table().begin();

	for (; j != g_mrd->group_table().end(); ++j) {
		group_node *node = j->second->node_owned_by(this);
		if (node) {
			((pim_group_node *)node)->lost_neighbour(neigh);
		}
	}
}

pim_neighbour *pim_router::get_neighbour(const inet6_addr &addr) const {
	for (mrd::interface_list::const_iterator i = g_mrd->intflist().begin();
			i != g_mrd->intflist().end(); ++i) {
		const interface *intf = i->second;
		pim_interface *pimintf = (pim_interface *)intf->node_owned_by(this);
		if (pimintf) {
			pim_neighbour *neigh = pimintf->get_neighbour(addr);
			if (neigh)
				return neigh;
		}
	}

	return 0;
}

pim_neighbour *pim_router::get_rpf_neighbour(const in6_addr &addr) const {
	inet6_addr nh;

	const mrib_def::prefix *p =
		g_mrd->mrib().resolve_nexthop(addr, inet6_addr::any(), nh);

	if (p && p->is_valid()) {
		if (!p->intf)
			return 0;

		pim_interface *pintf = get_interface(p->intf);
		if (pintf) {
			return pintf->get_neighbour(nh);
		}
	}

	return 0;
}

void pim_router::data_available(uint32_t) {
	int recvlen = pim_sock.recvfrom(g_mrd->ipktb->buffer(), g_mrd->ipktb->bufferlen());

	if (recvlen < 0) {
		if (should_log(WARNING))
			log().perror("recv failed");
		return;
	}

	if (recvlen < (int)sizeof(pim_message)) {
		// discard
		return;
	}

	sockaddr_in6 dst;
	int index;

	if (!pim_sock.destination_address(dst, index) || index == 0) {
		pim_message *pimmsg = g_mrd->ipktb->header<pim_message>();

		if (should_log(INTERNAL_FLOW)) {
			log().xprintf("Dropped %s message from %{addr}, no "
				      "input interface.\n", pimmsg->type_name(),
				      pim_sock.source_address().sin6_addr);
		}

		return;
	}

	g_mrd->ipktb->rlength = recvlen;
	g_mrd->ipktb->read_offset = 0;

	pim_interface *pimintf = get_interface(index);
	if (!pimintf) {
		pim_message *pimmsg = g_mrd->ipktb->header<pim_message>();

		if (should_log(INTERNAL_FLOW)) {
			log().xprintf("Dropped %s message from %{addr}, PIM "
				      "interface %i is disabled.\n",
				      pimmsg->type_name(),
				      pim_sock.source_address().sin6_addr,
				      index);
		}

		return;
	}

	g_mrd->ipktb->source = pimintf->owner();

	sockaddr_in6 _recvfrom = pim_sock.source_address();

	pimintf->data_available(&_recvfrom, &dst);
}

std::list<in6_addr> pim_router::all_global_addrs() const {
	std::list<in6_addr> addrs;

	const mrd::interface_list &intflist = g_mrd->intflist();

	for (mrd::interface_list::const_iterator i = intflist.begin();
							i != intflist.end(); ++i) {
		if (!i->second->up())
			continue;

		const std::set<inet6_addr> &gs = i->second->globals();
		for (std::set<inet6_addr>::const_iterator j = gs.begin();
							j != gs.end(); ++j) {
			addrs.push_back(*j);
		}
	}

	return addrs;
}

bool pim_router::sendmsg(const sockaddr_in6 *src, sockaddr_in6 *dst,
			 pim_message *msg, uint16_t len) const {
	sockaddr_in6 calc_src;

	if (!src) {
		src = &calc_src;

		if (IN6_IS_ADDR_LINKLOCAL(&dst->sin6_addr)) {
			interface *intf = g_mrd->get_interface_by_index(dst->sin6_scope_id);
			if (!intf)
				return false;

			calc_src = *intf->localaddr();
		} else if (!IN6_IS_ADDR_MULTICAST(&dst->sin6_addr)) {
			if (m_my_address.is_any()) {
				if (should_log(DEBUG)) {
					log().xprintf("Failed while sending %s"
						      " to %{addr}, no source "
						      "address.", msg->type_name(),
						      dst->sin6_addr);
				}

				return false;
			}

			memset(&calc_src, 0, sizeof(sockaddr_in6));

			calc_src.sin6_family = AF_INET6;
			calc_src.sin6_addr = m_my_address;
		} else {
			if (should_log(DEBUG)) {
				log().xprintf("Trying to send %s to %{addr} "
					      "without source address",
					      msg->type_name(), dst->sin6_addr);
			}

			return false;
		}
	}

	if (msg->checksum == 0) {
		msg->build_checksum(src->sin6_addr, dst->sin6_addr, len);
	}

	if (msg->type() != pim_msg_register && should_log(MESSAGE_SIG)) {
		log().xprintf("Sending %s message from %{addr} to %{addr} len "
			      "%u\n", msg->type_name(), src->sin6_addr,
			      dst->sin6_addr, (uint32_t)len);
	}

	if (pim_sock.sendto(msg, len, dst, src) < 0) {
		if (should_log(MESSAGE_ERR)) {
			log().xprintf("sendmsg to %{addr}%%%i from %{addr}%%%i"
				      " failed: %s\n", dst->sin6_addr,
				      (int)dst->sin6_scope_id, src->sin6_addr,
				      (int)src->sin6_scope_id, strerror(errno));
		}

		return false;
	}

	return true;
}

bool pim_router::send_all(pim_message *msg, uint16_t len,
				const sockaddr_in6 *from) const {
	bool res = true;

	for (mrd::interface_list::const_iterator i = g_mrd->intflist().begin();
			i != g_mrd->intflist().end(); ++i) {
		if (i->second->linklocals().empty())
			continue;

		/* Force the build of the checksum */
		msg->checksum = 0;

		pim_interface *intf = (pim_interface *)i->second->node_owned_by(this);
		if (intf) {
			if (intf->get_state() == pim_interface::NOT_READY)
				continue;

			if (from) {
				if (!sendmsg(from, &pim_all_routers_addr, msg, len))
					res = false;
			} else if (!i->second->linklocals().empty()) {
				if (!sendmsg(i->second->localaddr(), &pim_all_routers_addr, msg, len))
					res = false;
			}
		}
	}

	return res;
}

bool pim_router::send_all_neighbours(pim_message *msg, uint16_t len,
				     const sockaddr_in6 *from) const {
	bool res = true;

	for (mrd::interface_list::const_iterator i = g_mrd->intflist().begin();
			i != g_mrd->intflist().end(); ++i) {
		if (i->second->linklocals().empty())
			continue;

		/* Force the build of the checksum */
		msg->checksum = 0;

		pim_interface *intf = (pim_interface *)i->second->node_owned_by(this);
		if (intf) {
			if (intf->get_state() == pim_interface::NOT_READY)
				continue;

			if (intf->get_neighbours().empty())
				continue;

			if (from) {
				if (!sendmsg(from, &pim_all_routers_addr, msg, len))
					res = false;
			} else if (!i->second->linklocals().empty()) {
				if (!sendmsg(i->second->localaddr(), &pim_all_routers_addr, msg, len))
					res = false;
			}
		}
	}

	return res;
}

bool pim_router::send_register(const in6_addr &src, const in6_addr &dst,
			       pim_register_message *msg, int payload) const {
	return send_register_generic(src, dst, msg, payload, 0 /* XXX */);
}

bool pim_router::send_register_probe(const in6_addr &src, const in6_addr &dst,
				     pim_register_message *msg, int payload) const {
	return send_register_generic(src, dst, msg, payload, 0 /* XXX */);
}

bool pim_router::send_register_generic(const in6_addr &src, const in6_addr &dst,
				       pim_register_message *msg,
				       int payload, int statname) const {

	sockaddr_in6 srcaddr;
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.sin6_family = AF_INET6;
	srcaddr.sin6_addr = src;

	sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = dst;

	msg->build_checksum(src, dst, sizeof(pim_register_message));

	if (sendmsg(&srcaddr, &addr, msg, sizeof(pim_register_message) + payload)) {
		/* m_stats.counter(statname)++; */
		return true;
	}

	return false;
}

void pim_router::send_register_stop_to_router(const inet6_addr &grpid,
					      const in6_addr &from,
					      const in6_addr &src,
					      const in6_addr &to) const {
	pim_register_stop_message *msg = g_mrd->opktb->header<pim_register_stop_message>();

	msg->construct(grpid, src);

	sockaddr_in6 myaddr, dst;
	memset(&myaddr, 0, sizeof(myaddr));
	memset(&dst, 0, sizeof(dst));

	myaddr.sin6_family = AF_INET6;
	myaddr.sin6_addr = from;

	dst.sin6_family = AF_INET6;
	dst.sin6_addr = to;

	pim->sendmsg(&myaddr, &dst, msg, sizeof(pim_register_stop_message));
}

void pim_router::dr_changed(pim_interface *intf, bool islocal) {
	mrd::group_list::const_iterator j = g_mrd->group_table().begin();

	for (; j != g_mrd->group_table().end(); ++j) {
		group_node *node = j->second->node_owned_by(this);
		if (node) {
			((pim_group_node *)node)->dr_changed(intf, islocal);
		}
	}
}

void pim_router::event(int event, void *ptr) {
	if (event != mrd::CreatedGroup) {
		router::event(event, ptr);
		return;
	}

	mrd::create_group_context *ctx = (mrd::create_group_context *)ptr;

	if (ctx->result) {
		pim_group_node *gr = get_group(ctx->groupaddr);
		if (gr) {
			/* XXX origin=0, force origin existance? */
			source_discovery_origin *origin =
				g_mrd->get_source_discovery(ctx->origin_name.c_str());

			interface *intf =
				g_mrd->get_interface_by_index(ctx->iif);

			gr->discovered_source(intf, ctx->requester, origin);
		}
	}

	delete ctx;
}

void pim_router::discovered_source(interface *input,
				   const inet6_addr &groupaddr,
				   const inet6_addr &sourceaddr,
				   source_discovery_origin *origin) {
	pim_group_node *gr = get_group(groupaddr);

	if (gr) {
		gr->discovered_source(input, sourceaddr, origin);
	} else {
		/* only create groups for local sources */
		if (!g_mrd->in_same_subnet(sourceaddr)) {
			if (should_log(MESSAGE_SIG)) {
				log().xprintf("Not creating Group state for "
					      "(%{Addr}, %{Addr}) as it isn't "
					      "local: source address doesn't "
					      "match any of the router's "
					      "prefixes.\n", sourceaddr, groupaddr);
			}

			return;
		}

		mrd::create_group_context *ctx = new mrd::create_group_context;

		if (!ctx)
			return;

		ctx->iif = input ? input->index() : 0;
		ctx->groupaddr = groupaddr;
		ctx->requester = sourceaddr;

		if (origin)
			ctx->origin_name = origin->origin_description();

		g_mrd->create_group(this, this, ctx);
	}
}

void pim_router::mfa_notify(mfa_group_source *srcstate, const in6_addr &grp, const in6_addr &src,
			uint32_t flags, mfa_group_source::action act, interface *iif,
			ip6_hdr *hdr, uint16_t plen, uint16_t flen) {

	pim_group_node *node = 0;
	pim_group_source_state *state = 0;

	if (!srcstate || !srcstate->instowner) {
		node = get_group(grp);
		if (!node)
			return;

		state = node->get_state(src);
		if (!state)
			return;
	} else {
		state = (pim_group_source_state *)srcstate->instowner;
		node = state->owner();
	}

	if (!state->spt()) {
		if (state->iif() == iif) {
			state->set_spt(true);
		} else if (node->has_wildcard() && node->wildcard()->iif() != iif) {
			/* XXX We will never reach here as in our current
			 * design, iif of (S,G) is always RPF_interface(S) */
			state->set_spt(true);
		}
	}

	if (state->iif() == iif && state->is_source_local()) {
		state->restart_kat();

		/* encapsulate locally received packets to the RP */
		if (flags & mfa_group_source::f_any_incoming && !node->is_ssm() && !node->is_self_rp())
			state->forward_to_rp(iif, hdr, plen);
	} else if (flags & mfa_group_source::f_wrong_iif) {
		/* if the incoming interface is a Oif for (S,G) */
		state->trigger_assert(iif);
	}
}


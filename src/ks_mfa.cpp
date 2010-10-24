/*
 * Multicast Routing Daemon (MRD)
 *   ks_mfa.cpp
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
#include <fcntl.h>
#include <unistd.h>
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/mrd.h>
#include <mrd/router.h>
#include <mrdpriv/ks_mfa.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#else
#include <net/route.h>
#endif
#ifdef OS_LINUX
#include <linux/mroute6.h>
#else
#include <netinet6/ip6_mroute.h>
#include <netinet6/in6_var.h>
#endif
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef _NETBSD_SOURCE
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

ks_mfa_group_source::ks_mfa_group_source(ks_mfa_group *grp, const in6_addr &addr,
						uint32_t flags, action *acts)
	: m_owner(grp), m_addr(addr) {

	instowner = 0;

	m_flags = flags;

	m_interest_flags = 0;

	for (int i = 0; i < event_count; i++)
		change_flags(1 << i, acts[i]);

	m_iif = 0;

	memset(&m_ks_state, 0, sizeof(m_ks_state));

	m_ks_state.mf6cc_origin = m_addr.as_sockaddr();
	m_ks_state.mf6cc_mcastgrp = m_owner->addr().as_sockaddr();
}

ks_mfa_group_source::~ks_mfa_group_source() {
	((ks_mfa *)g_mrd->mfa())->commit(&m_ks_state, true);
}

void ks_mfa_group_source::get_input_counter(uint64_t &val) const {
	((ks_mfa *)g_mrd->mfa())->get_input_counter(this, val);
}

void ks_mfa_group_source::get_forwarding_counter(uint64_t &val) const {
	((ks_mfa *)g_mrd->mfa())->get_forwarding_counter(this, val);
}

void ks_mfa_group_source::set_iif(interface *iif) {
	m_iif = iif;

	m_ks_state.mf6cc_parent = iif ? ((ks_mfa *)g_mrd->mfa())->vif(iif) : 0;

	((ks_mfa *)g_mrd->mfa())->commit(&m_ks_state);
}

void ks_mfa_group_source::release_iif(interface *iif) {
	if (m_iif == iif) {
		set_iif(0);
	}
}

void ks_mfa_group_source::add_oif(interface *oif) {
	int vif = ((ks_mfa *)g_mrd->mfa())->vif(oif);

	if (vif < 0)
		return;

	if (!has_oif(oif)) {
		m_oifs.push_back(oif);
	}

	IF_SET(vif, &m_ks_state.mf6cc_ifset);

	((ks_mfa *)g_mrd->mfa())->commit(&m_ks_state);
}

void ks_mfa_group_source::release_oif(interface *oif) {
	for (oifs::iterator k = m_oifs.begin(); k != m_oifs.end(); ++k) {
		if (*k == oif) {
			m_oifs.erase(k);

			int vif = ((ks_mfa *)g_mrd->mfa())->vif(oif);

			if (vif >= 0) {
				IF_CLR(vif, &m_ks_state.mf6cc_ifset);
				((ks_mfa *)g_mrd->mfa())->commit(&m_ks_state);
			}

			return;
		}
	}
}

void ks_mfa_group_source::change_flags(uint32_t flags, action act) {
	if (act == no_action) {
		m_interest_flags &= ~flags;
	} else {
		m_interest_flags |= flags;
	}
}

static void output(base_stream &out, const std::vector<interface *> &ifs) {
	out.write("{");
	for (std::vector<interface *>::const_iterator i = ifs.begin();
						i != ifs.end(); ++i) {
		if (i != ifs.begin())
			out.write(", ");
		out.write((*i)->name());
	}
	out.write("}");
}

void ks_mfa_group_source::output_info(base_stream &out) const {
	out.xprintf("Iif: %s\n", m_iif ? m_iif->name() : "(None)");
	base_stream &oso = out.write("Oifs: ");
	output(oso, m_oifs);
	oso.newl();
}

ks_mfa_group::ks_mfa_group(router *owner, const inet6_addr &id)
	: mfa_group(owner), m_addr(id) {
	instowner = 0;

	ks_mfa *m = (ks_mfa *)g_mrd->mfa();

	m_flags = m->m_grpflags;
	for (int i = 0; i < mfa_group_source::event_count; i++)
		m_actions[i] = m->m_grpactions[i];

	m_state = pending;
}

void ks_mfa_group::activate(bool accept) {
	if (accept && m_state == running)
		return;

	if (!accept) {
		m_state = denied;
	} else {
		m_state = running;
	}

	if (!accept) {
		((ks_mfa *)g_mrd->mfa())->release_group(this);
	}
}

mfa_group_source *ks_mfa_group::create_source_state(const in6_addr &addr, void *instowner) {
	mfa_group_source *src = get_source_state(addr);

	if (!src) {
		src = new ks_mfa_group_source(this, addr, m_flags, m_actions);
		if (src) {
			if (mfa_core::mfa()->should_log(DEBUG))
				mfa_core::mfa()->log().xprintf(
					"MFA: created source state for %{addr}\n", addr);
			m_sources[addr] = (ks_mfa_group_source *)src;
		}
	}

	if (src)
		src->instowner = instowner;

	return src;
}

mfa_group_source *ks_mfa_group::get_source_state(const in6_addr &addr) const {
	return match_source(addr);
}

void ks_mfa_group::release_source_state(mfa_group_source *_src) {
	ks_mfa_group_source *src = (ks_mfa_group_source *)_src;

	for (sources::iterator i = m_sources.begin();
					i != m_sources.end(); ++i) {
		if (src == i->second) {
			delete src;
			m_sources.erase(i);

			return;
		}
	}
}

void ks_mfa_group::change_default_flags(uint32_t flags,
					mfa_group_source::action act) {
	for (int i = mfa_group_source::any_incoming;
			i < mfa_group_source::event_count; i++) {
		if (flags & (1 << i))
			m_actions[i] = act;
	}
}

void ks_mfa_group::output_info(base_stream &out) const {
	for (sources::const_iterator i = m_sources.begin();
					i != m_sources.end(); ++i) {
		out.writeline(i->first);
		out.inc_level();
		i->second->output_info(out);
		out.dec_level();
	}
}

void ks_mfa::change_group_default_flags(uint32_t flags,
					mfa_group_source::action act) {
	for (int i = mfa_group_source::any_incoming;
			i < mfa_group_source::event_count; i++) {
		if (flags & (1 << i))
			m_grpactions[i] = act;
	}
}

mfa_group *ks_mfa::create_group(router *r, const inet6_addr &id, void *instowner) {
	mfa_group *grp = get_group(id);

	if (!grp) {
		grp = new ks_mfa_group(r, id);
		if (grp) {
			if (mfa_core::mfa()->should_log(DEBUG))
				mfa_core::mfa()->log().xprintf(
					"MFA: created group state for %{Addr}\n", id);
			m_groups[id] = (ks_mfa_group *)grp;
		}
	}

	if (grp)
		grp->instowner = instowner;

	return grp;
}

mfa_group *ks_mfa::get_group(const inet6_addr &id) const {
	groups::const_iterator k = m_groups.find(id);

	if (k == m_groups.end())
		return 0;

	return k->second;
}

void ks_mfa::release_group(mfa_group *grp) {
	for (groups::iterator i = m_groups.begin(); i != m_groups.end(); ++i) {
		if (grp == i->second) {
			delete i->second;

			m_groups.erase(i);

			return;
		}
	}
}

ks_mfa::ks_mfa()
	: m_sock("kernel sock", this, std::mem_fun(&ks_mfa::kernel_data_pending)) {
	m_icmpsock = -1;
	m_grpflags = 0;
	for (int i = 0; i < mfa_group_source::event_count; i++)
		m_grpactions[i] = mfa_group_source::no_action;
}

bool ks_mfa::pre_startup() {
	if (!mfa_core::pre_startup())
		return false;

	if (!data_plane_sourcedisc.check_startup())
		return false;

	m_icmpsock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (m_icmpsock < 0) {
		if (should_log(WARNING))
			log().perror("(MFA) Failed to create ICMPv6 socket");
		return false;
	}

	int vers = 1;

	if (setsockopt(m_icmpsock, IPPROTO_IPV6, MRT6_INIT, &vers, sizeof(vers)) < 0) {
		if (should_log(WARNING))
			log().perror("(MFA) MRT6_INIT Failed");
	}

#if 0
	if (setsockopt(m_icmpsock, IPPROTO_IPV6, MRT6_PIM, &vers, sizeof(vers)) < 0) {
		g_mrd->log().info(DEBUG) << "MFA: MRD6_PIM Failed: " << strerror(errno) << endl;
	}
#endif

	m_sock.register_fd(m_icmpsock);

	return g_mrd->register_source_discovery("data-plane",
						&data_plane_sourcedisc);
}

bool ks_mfa::check_startup() {
	return true;
}

void ks_mfa::shutdown() {
	setsockopt(m_icmpsock, IPPROTO_IPV6, MRT6_DONE, 0, 0);

	if (m_icmpsock > 0) {
		close(m_icmpsock);
	}

	g_mrd->register_source_discovery("data-plane", 0);
}

void ks_mfa::forward(interface *intf, ip6_hdr *hdr, uint16_t len) const {
	if (should_log(WARNING))
		log().writeline("(MFA) Failed to dispatch, not supported.");
}

bool ks_mfa::output_info(base_stream &out, const std::vector<std::string> &args) const {
	for (groups::const_iterator i = m_groups.begin();
				i != m_groups.end(); ++i) {
		out.writeline(i->first);
		out.inc_level();
		i->second->output_info(out);
		out.dec_level();
	}

	return true;
}

void ks_mfa::added_interface(interface *intf) {
	for (int vif = 1; vif < MAXMIFS; vif++) {
		if (rev_vifs.find(vif) == rev_vifs.end()) {
			mif6ctl mc;
			mc.mif6c_mifi = vif;
			mc.mif6c_flags = 0;
			mc.mif6c_pifi = intf->index();

			if (setsockopt(m_icmpsock, IPPROTO_IPV6, MRT6_ADD_MIF, &mc, sizeof(mc)) < 0) {
				if (should_log(WARNING))
					log().perror("(MFA) Failed to MRT6_ADD_MIF");
			} else {
				vifs[intf] = vif;
				rev_vifs[vif] = intf;

				if (should_log(DEBUG))
					log().xprintf("(MFA) Added interface %s with vif %i\n",
						      intf->name(), vif);
			}

			return;
		}
	}

	if (should_log(WARNING))
		log().xprintf("(MFA) Failed to enable multicast "
			      "forwarding in %s, no available MIFs\n",
			      intf->name());
}

void ks_mfa::removed_interface(interface *intf) {
	if (should_log(DEBUG))
		log().xprintf("(MFA) Removed interface %s.\n", intf->name());

	std::map<interface *, int>::iterator i = vifs.find(intf);
	if (i != vifs.end()) {
		uint16_t index = i->second;

		vifs.erase(i);

		rev_vifs.erase(rev_vifs.find(index));

		setsockopt(m_icmpsock, IPPROTO_IPV6, MRT6_DEL_MIF, &index, sizeof(index));
	}
}

int ks_mfa::vif(interface *iif) const {
	std::map<interface *, int>::const_iterator i = vifs.find(iif);
	if (i != vifs.end())
		return i->second;
	return -1;
}

void ks_mfa::commit(mf6cctl *msg, bool remove) {
	if (IN6_IS_ADDR_UNSPECIFIED(&msg->mf6cc_origin.sin6_addr))
		return;

	if (should_log(EXTRADEBUG)) {
		log().xprintf("(MFA) Commited MFC with src: %{addr} dst: %{addr}\n",
			      msg->mf6cc_origin.sin6_addr, msg->mf6cc_mcastgrp.sin6_addr);
	}

	if (setsockopt(m_icmpsock, IPPROTO_IPV6,
		       remove ? MRT6_DEL_MFC : MRT6_ADD_MFC,
		       msg, sizeof(*msg)) < 0) {
		if (should_log(DEBUG))
			log().perror("Failed to commit MFC");
	}
}

static uint8_t buf[2048];

void ks_mfa::kernel_data_pending(uint32_t) {
	sockaddr_in6 from;
	socklen_t slen = sizeof(from);

	int len = recvfrom(m_icmpsock, buf, sizeof(buf), 0, (sockaddr *)&from, &slen);

	if (len > 0) {
		icmp6_hdr *hdr = (icmp6_hdr *)buf;

		if (hdr->icmp6_type == 0) {
			mrt6msg *msg = (mrt6msg *)hdr;

			std::map<int, interface *>::const_iterator i = rev_vifs.find(msg->im6_mif);
			if (i == rev_vifs.end()) {
				return;
			}

			if (msg->im6_msgtype == MRT6MSG_NOCACHE) {

#if 1
				if (should_log(DEBUG))
					log().xprintf("(MFA) Cache miss mif %s src %{addr} dst %{addr}\n",
						      i->second->name(), msg->im6_src, msg->im6_dst);
#endif

				discovered_source(i->second->index(), msg->im6_dst, msg->im6_src);
			} else if (msg->im6_msgtype == MRT6MSG_WRONGMIF) {
				ks_mfa_group *grp = (ks_mfa_group *)get_group(msg->im6_dst);
				if (grp) {
					grp->owner()->mfa_notify(
							grp->get_source_state(msg->im6_src),
							msg->im6_dst, msg->im6_src,
							mfa_group_source::f_wrong_iif,
							mfa_group_source::notify_no_copy,
							i->second, 0, 0, 0);
				}
			} else if (msg->im6_msgtype == MRT6MSG_WHOLEPKT) {
				/* we don't use BSD PIM tunnels */
			}
		}
	}
}

void ks_mfa::discovered_source(int ifindex, const inet6_addr &grp,
				const inet6_addr &src) {
	data_plane_sourcedisc.discovered_source(ifindex, grp, src);
}

void ks_mfa::get_source_counters(const ks_mfa_group_source *src, sioc_sg_req6 *r) {
	r->src = src->m_addr.as_sockaddr();
	r->grp = src->m_owner->addr().as_sockaddr();

	if (ioctl(m_icmpsock, SIOCGETSGCNT_IN6, r) < 0) {
		r->pktcnt = 0;
		r->bytecnt = 0;
		r->wrong_if = 0;
	}
}

void ks_mfa::get_input_counter(const ks_mfa_group_source *src, uint64_t &val) {
	sioc_sg_req6 r;

	get_source_counters(src, &r);

	val = r.bytecnt;
}

void ks_mfa::get_forwarding_counter(const ks_mfa_group_source *src, uint64_t &val) {
	sioc_sg_req6 r;

	get_source_counters(src, &r);

	val = r.bytecnt - r.wrong_if;
}


/*
 * Multicast Routing Daemon (MRD)
 *   us_mfa.cpp
 *
 * Copyright (C) 2009 - Teemu Kiviniemi
 * Copyright (C) 2009 - CSC - IT Center for Science Ltd.
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

#include <mrdpriv/linux/us_mfa.h>

#include <mrd/mrd.h>
#include <mrd/interface.h>
#include <mrd/router.h>
#include <mrd/icmp.h>

#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <netinet/icmp6.h>

us_mfa_group_source::us_mfa_group_source(us_mfa_group *grp, const in6_addr &addr,
					 uint32_t flags, action *acts)
	: m_owner(grp), m_addr(addr) {

	instowner = 0;

	m_flags = flags;

	m_interest_flags = 0;

	for (int i = 0; i < event_count; i++)
		change_flags(1 << i, acts[i]);

	memset(m_stats, 0, sizeof(m_stats));

	m_fw_bag = 0;
	m_fw_pkt_bag = 0;

	m_iif = 0;

	stat_octet_count60s = 0;
	stat_packet_count60s = 0;
}

void us_mfa_group_source::set_iif(interface *iif) {
	m_iif = iif;
}

void us_mfa_group_source::release_iif(interface *iif) {
	if (m_iif == iif)
		m_iif = 0;
}

void us_mfa_group_source::add_oif(interface *oif) {
	if (!has_oif(oif)) {
		m_oifs.push_back(oif);

#ifndef LINUX_NO_TRANSLATOR
		us_mfa *mfa = (us_mfa *) g_mrd->mfa();
		const in6_addr &grp = *m_owner->m_addr;

		/* Inform translator about the MTU of oif. */
		mfa->m_translator.set_mtu(grp, oif->mtu());

		/* First oif. Enable source state in translator. */
		if (m_oifs.size() == 1)
			mfa->m_translator.change_source_state(grp, m_addr, true);
#endif
	}
}

void us_mfa_group_source::release_oif(interface *oif) {
	for (oifs::iterator k = m_oifs.begin(); k != m_oifs.end(); ++k) {
		if (*k == oif) {
			m_oifs.erase(k);
#ifndef LINUX_NO_TRANSLATOR
			if (m_oifs.size() == 0) {
				/* Last oif. Disable source state in translator. */
				us_mfa *mfa = (us_mfa *) g_mrd->mfa();
				mfa->m_translator.change_source_state(*m_owner->m_addr,
						m_addr, false);
			}
#endif
			return;
		}
	}
}

void us_mfa_group_source::change_flags(uint32_t flags, action act) {
	if (act == no_action) {
		m_interest_flags &= ~flags;
	} else {
		m_interest_flags |= flags;
	}
}

void us_mfa_group_source::update_stats() {
	stat_octet_count60s = (uint64_t)floor(stat_octet_count60s * (29/30.)) + m_fw_bag;
	stat_packet_count60s = (uint64_t)floor(stat_packet_count60s * (29/30.)) + m_fw_pkt_bag;

	m_fw_bag = 0;
	m_fw_pkt_bag = 0;
}

void us_mfa_group_source::route(int iif, ip6_hdr *hdr, uint16_t len) {
	uint32_t f = f_any_incoming;

	if (is_iif(iif)) {
		m_stats[stat_input] += len;

		int count = 0;

		for (oifs::const_iterator i = m_oifs.begin();
						i != m_oifs.end(); ++i) {
			if ((*i)->index() == iif)
				continue;

			((us_mfa *)g_mrd->mfa())->forward(*i, hdr, len);

			count ++;
		}

		if (count) {
			m_stats[stat_forwarded] ++;
			m_stats[stat_forwarded_size] += len;

			m_fw_bag += len;
			m_fw_pkt_bag ++;

			m_owner->m_fw_bag += len;
			m_owner->m_fw_pkt_bag ++;
		}
	} else {
		f |= f_wrong_iif;
		m_stats[stat_wrong_iif]++;
	}

	if (f & m_interest_flags) {
		m_owner->owner()->mfa_notify(this, hdr->ip6_dst, hdr->ip6_src,
				f & m_interest_flags, copy_full_packet,
				g_mrd->get_interface_by_index(iif),
				hdr, len, len);
	}
}

void us_mfa_group_source::clear_interface_references(const inet6_addr &grpid, interface *intf) {
	if (is_iif(intf->index())) {
		if (mfa_core::mfa()->should_log(EXTRADEBUG)) {
			mfa_core::mfa()->log().xprintf(
				"(%{addr}, %{Addr}) releasing Iif %s as it was"
				"removed.\n", m_addr, grpid, intf->name());
		}

		release_iif(intf);
	}

	if (has_oif(intf)) {
		if (mfa_core::mfa()->should_log(EXTRADEBUG)) {
			mfa_core::mfa()->log().xprintf(
				"(%{addr}, %{Addr}) releasing Oif %s as it was "
				"removed.\n", m_addr, grpid, intf->name());
		}

		release_oif(intf);
	}
}

static void output(base_stream &out, const std::vector<interface *> &ifs) {
	out.write("{ ");
	for (std::vector<interface *>::const_iterator i = ifs.begin();
						i != ifs.end(); ++i) {
		if (i != ifs.begin())
			out.write(", ");
		out.write((*i)->name());
	}
	out.write(" }");
}

void us_mfa_group_source::output_info(base_stream &out, bool counters, bool noempty) const {
	if (counters) {
		if (noempty && !stat_packet_count60s)
			return;

		out.xprintf("%{addr}", m_addr);

		out.inc_level();

		if (stat_packet_count60s) {
			out.write(" Activity statistics: ");

			const char *format = "%.2f %s";
			double rate = 8 * stat_octet_count60s / 60000.;
			const char *unit = "Kb/s";

			if (rate > 1000) {
				rate /= 1000.;
				unit = "Mb/s";
			}

			out.printf(format, rate, unit);
			out.printf(" (%.2f pkt/s)", stat_packet_count60s / 60.f);
			out.newl();
			out.printf("Last 60 secs: %llu bytes (%llu packets, %.2lf bytes/packet)",
				   stat_octet_count60s, stat_packet_count60s,
				   stat_octet_count60s / (double)stat_packet_count60s);
			out.newl();
		} else {
			out.writeline(" No activity in the last 60 seconds");
		}

		out.dec_level();

	} else {
		out.xprintf("%{addr} from %s to ", m_addr, m_iif ? m_iif->name() : "(None)");
		output(out, m_oifs);
		out.newl();
	}
}

void us_mfa_group_source::get_input_counter(uint64_t &bytes) const {
	bytes = m_stats[stat_input];
}

void us_mfa_group_source::get_forwarding_counter(uint64_t &bytes) const {
	bytes = m_fw_bag;
}

us_mfa_group::us_mfa_group(router *owner, const inet6_addr &id)
	: mfa_group(owner) {

#ifndef LINUX_NO_TRANSLATOR
	m_addr = id.address_p();
#endif

	instowner = 0;

	us_mfa *m = (us_mfa *)g_mrd->mfa();

	m_flags = m->m_grpflags;
	for (int i = 0; i < mfa_group_source::event_count; i++)
		m_actions[i] = m->m_grpactions[i];

	m_state = pending;

	invalidate_source_cache();
	m_useful_cache = false;

	m_fw_bag = 0;
	m_fw_pkt_bag = 0;

	stat_octet_count60s = 0;
	stat_packet_count60s = 0;
}

void us_mfa_group::activate(bool accept) {
	if (accept && m_state == running)
		return;

	if (!accept) {
		m_state = denied;
	} else {
		m_state = running;
	}

	if (!accept) {
		((us_mfa *)g_mrd->mfa())->release_group(this);
	}
}

void us_mfa_group::route(int iif, ip6_hdr *hdr, uint16_t len) {
	if (m_state == denied)
		return;
	else if (m_state == pending) {
		return;
	}

	us_mfa_group_source *src = match_source(hdr->ip6_src);

	if (src) {
		src->route(iif, hdr, len);
	} else {
		((us_mfa *)g_mrd->mfa())->discovered_source(iif, hdr->ip6_dst,
							    hdr->ip6_src);
	}
}

void us_mfa_group::clear_interface_references(const inet6_addr &grpid, interface *intf) {
	for (sources::iterator i = m_sources.begin();
				i != m_sources.end(); ++i) {
		i->second->clear_interface_references(grpid, intf);
	}
}

void us_mfa_group::invalidate_source_cache() {
	memset(m_source_cache, 0, sizeof(m_source_cache));
}

#ifndef LINUX_NO_TRANSLATOR
/* Group address */
const in6_addr &us_mfa_group::id() const {
	return *m_addr;
}
#endif

mfa_group_source *us_mfa_group::create_source_state(const in6_addr &addr, void *instowner) {
	mfa_group_source *src = get_source_state(addr);

	if (!src) {
		src = new us_mfa_group_source(this, addr, m_flags, m_actions);
		if (src) {
			if (mfa_core::mfa()->should_log(EXTRADEBUG))
				mfa_core::mfa()->log().xprintf("Created source state for %{addr}.\n", addr);

			m_sources[addr] = (us_mfa_group_source *)src;

			m_useful_cache = m_sources.size() < _SOURCE_CACHE_LEN;
		}
	}

	if (src)
		src->instowner = instowner;

	return src;
}

mfa_group_source *us_mfa_group::get_source_state(const in6_addr &addr) const {
	return match_source(addr);
}

void us_mfa_group::update_stats() {
	for (sources::iterator i = m_sources.begin();
				i != m_sources.end(); ++i) {
		i->second->update_stats();
	}

	stat_octet_count60s = (uint64_t)ceil(stat_octet_count60s * (29/30.)) + m_fw_bag;
	stat_packet_count60s = (uint64_t)ceil(stat_packet_count60s * (29/30.)) + m_fw_pkt_bag;

	m_fw_bag = 0;
	m_fw_pkt_bag = 0;
}

void us_mfa_group::release_source_state(mfa_group_source *_src) {
	us_mfa_group_source *src = (us_mfa_group_source *)_src;

	for (sources::iterator i = m_sources.begin();
					i != m_sources.end(); ++i) {
		if (src == i->second) {
			delete src;
			m_sources.erase(i);

			invalidate_source_cache();
			m_useful_cache = m_sources.size() < _SOURCE_CACHE_LEN;

			return;
		}
	}
}

void us_mfa_group::change_default_flags(uint32_t flags,
					mfa_group_source::action act) {
	for (int i = mfa_group_source::any_incoming;
			i < mfa_group_source::event_count; i++) {
		if (flags & (1 << i))
			m_actions[i] = act;
	}
}

void us_mfa_group::output_info(base_stream &out, bool counters, bool noempty) const {
	if (counters) {
		out.writeline("Aggregate activity statistics:");
		out.inc_level();

		if (stat_packet_count60s) {
			const char *format = "%.2f %s";
			double rate = 8 * stat_octet_count60s / 60000.;
			const char *unit = "Kb/s";

			if (rate > 1000) {
				rate /= 1000.;
				unit = "Mb/s";
			}

			out.write("Current rate: ");
			out.printf(format, rate, unit);
			out.printf(" (%.2f pkt/s)", stat_packet_count60s / 60.f);
			out.newl();
			out.printf("Last 60 secs: %llu bytes (%llu packets, %.2lf bytes/packet)",
					stat_octet_count60s, stat_packet_count60s,
					stat_octet_count60s / (double)stat_packet_count60s);
			out.newl();
		} else {
			out.writeline("No available statistics");
		}

		out.dec_level();
	}

	/* no active sources */
	if (counters && noempty && !stat_packet_count60s)
		return;

	out.writeline("Sources:");

	out.inc_level();

	if (m_sources.empty()) {
		out.writeline("(None)");
	} else {
		for (sources::const_iterator i = m_sources.begin();
					i != m_sources.end(); ++i) {
			i->second->output_info(out, counters, noempty);
		}
	}

	out.dec_level();
}

void us_mfa::change_group_default_flags(uint32_t flags,
					mfa_group_source::action act) {
	for (int i = mfa_group_source::any_incoming;
			i < mfa_group_source::event_count; i++) {
		if (flags & (1 << i))
			m_grpactions[i] = act;
	}
}

mfa_group *us_mfa::create_group(router *r, const inet6_addr &id, void *instowner) {
	mfa_group *grp = get_group(id);

	if (!grp) {
		grp = new us_mfa_group(r, id);
		if (grp) {
			if (mfa_core::mfa()->should_log(EXTRADEBUG))
				mfa_core::mfa()->log().xprintf("Create state for group %{Addr}.\n", id);

#ifndef LINUX_NO_TRANSLATOR
			m_translator.change_group_state(id, true);
#endif
			m_groups[id] = (us_mfa_group *)grp;

			m_singles.clear();
			invalidate_group_cache(id);
		}
	}

	if (grp)
		grp->instowner = instowner;

	return grp;
}

mfa_group *us_mfa::get_group(const inet6_addr &id) const {
	groups::const_iterator k = m_groups.find(id);

	if (k == m_groups.end())
		return 0;

	return k->second;
}

void us_mfa::release_group(mfa_group *grp) {
	for (groups::iterator i = m_groups.begin(); i != m_groups.end(); ++i) {
		if (grp == i->second) {

#ifndef LINUX_NO_TRANSLATOR
			m_translator.change_group_state(i->first, false);
#endif
			delete i->second;

			m_groups.erase(i);

			m_singles.clear();
			invalidate_group_cache();

			return;
		}
	}
}

void us_mfa::invalidate_group_cache() {
	memset(m_grp_cache, 0, sizeof(m_grp_cache));
	m_singles.clear();
}

void us_mfa::invalidate_group_cache(const in6_addr &addr) {
	m_grp_cache[_GROUP_CACHE_HASH(addr)].entry = 0;

	singles::iterator i = m_singles.find(addr);
	if (i != m_singles.end())
		m_singles.erase(i);
}

us_mfa::us_mfa()
	: m_rawsock("us-mfa sock", this,
		    std::mem_fun(&us_mfa::data_available)),
#ifndef LINUX_NO_TRANSLATOR
	  m_translator(this),
#endif
	  m_stat_timer("mfa stat update timer", this,
		       std::mem_fun(&us_mfa::update_stats), 2000, true) {
#ifndef LINUX_NO_MMAP
	m_mmaped = 0;
	m_framesize = 2048;
	m_mmapedlen = 1024 * 1024;
#endif

	m_grpflags = 0;
	for (int i = 0; i < mfa_group_source::event_count; i++)
		m_grpactions[i] = mfa_group_source::no_action;

	invalidate_group_cache();
}

bool us_mfa::pre_startup() {
	if (!mfa_core::pre_startup())
		return false;

#ifndef LINUX_NO_TRANSLATOR
	if (!m_translator.pre_startup())
		return false;
#endif

	if (!m_sourcedisc.check_startup())
		return false;

	return g_mrd->register_source_discovery("data-plane", &m_sourcedisc);
}

bool us_mfa::check_startup() {
	bool bridges = g_mrd->get_property_bool("handle-proper-bridge");

	int sock = socket(PF_PACKET, SOCK_DGRAM, htons(bridges ? ETH_P_ALL : ETH_P_IPV6));
	if (sock < 0) {
		should_log(FATAL);

		if (errno == EPERM) {
			log().writeline("Administrative privileges are required to run mrd.");
		} else {
			log().perror("Failed to create packet socket");
		}
		return false;
	}

#ifndef LINUX_NO_TRANSLATOR
	if (!m_translator.check_startup())
		return false;
#endif

#ifndef LINUX_NO_MMAP
	if (g_mrd->has_property("mfa-framesize")) {
		m_framesize = atoi(g_mrd->get_property_string("mfa-framesize"));
		if (m_framesize < 2048)
			m_framesize = 2048;
	}

	uint32_t block_max_size = 256 * 1024;

	if (g_mrd->has_property("mfa-mmap-size")) {
		m_mmapedlen = atoi(g_mrd->get_property_string("mfa-mmap-size"));
		m_mmapedlen &= ~(0x1000-1);
		if (m_mmapedlen < block_max_size)
			m_mmapedlen = block_max_size;
	}

	tpacket_req req;

	req.tp_frame_size = m_framesize;

	req.tp_block_size = block_max_size;
	req.tp_block_nr = m_mmapedlen / block_max_size;
	req.tp_frame_nr = m_mmapedlen / req.tp_frame_size;

	m_mmapedlen = req.tp_block_nr * block_max_size;

	if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING,
				(void *)&req, sizeof(req)) == 0) {
		if ((m_mmaped = mmap(0, m_mmapedlen,
					PROT_READ|PROT_WRITE, MAP_SHARED,
					sock, 0)) == MAP_FAILED) {
			m_mmaped = 0;
		} else {
			m_mmapbuf = (uint8_t *)m_mmaped;
		}
	}

	if (!m_mmaped && should_log(WARNING)) {
		log().perror("Failed to memory map packet socket, continuing with socket interface");
	}
#endif

	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
		should_log(FATAL);
		log().writeline("Failed to change working socket to non-blocking mode.");
		return false;
	}

	int val = 256 * 1024;

	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));

	m_rawsock.register_fd(sock);

	m_stat_timer.start();

	return true;
}

void us_mfa::shutdown() {
#ifndef LINUX_NO_MMAP
	if (m_mmaped) {
		munmap(m_mmaped, m_mmapedlen);

		tpacket_req req;
		memset(&req, 0, sizeof(req));
		setsockopt(m_rawsock.fd(), SOL_PACKET, PACKET_RX_RING,
				&req, sizeof(req));
	}
#endif

	m_rawsock.unregister();

	g_mrd->register_source_discovery("data-plane", 0);
}

void us_mfa::discovered_source(int ifindex, const inet6_addr &grp,
			       const inet6_addr &src) {
	m_sourcedisc.discovered_source(ifindex, grp, src);
}

void us_mfa::update_stats() {
	for (groups::const_iterator k = m_groups.begin();
				k != m_groups.end(); ++k) {
		k->second->update_stats();
	}
}

#define MAX_EAT_ONE_CYCLE 100

void us_mfa::data_available(uint32_t) {
#ifndef LINUX_NO_MMAP
	if (m_mmaped) {
		int i = 0;
		while (i < MAX_EAT_ONE_CYCLE && *(unsigned long *)m_mmapbuf) {
			tpacket_hdr *hdr = (tpacket_hdr *)m_mmapbuf;
			sockaddr_ll *sa = (sockaddr_ll *)(((uint8_t *)hdr)
					+ TPACKET_ALIGN(sizeof(*hdr)));
			uint8_t *bp = ((uint8_t *)hdr) + hdr->tp_mac;

			if (sa->sll_protocol == htons(ETH_P_IPV6)
				&& sa->sll_pkttype != PACKET_OUTGOING)
				handle_ipv6(sa->sll_ifindex, bp, hdr->tp_len);

			hdr->tp_status = 0;
			m_mmapbuf += m_framesize;
			if (m_mmapbuf >= (((uint8_t *)m_mmaped) + m_mmapedlen))
				m_mmapbuf = (uint8_t *)m_mmaped;
			i++;
		}
	} else {
#endif
		sockaddr_ll sa;
		socklen_t salen = sizeof(sa);

		int len;

		while ((len = g_mrd->ipktb->recvfrom(m_rawsock.fd(),
					(sockaddr *)&sa, &salen)) > 0) {
			if (sa.sll_protocol == htons(ETH_P_IPV6)
				&& sa.sll_pkttype != PACKET_OUTGOING)
				handle_ipv6(sa.sll_ifindex,
					g_mrd->ipktb->buffer(), len);
		}
#ifndef LINUX_NO_MMAP
	}
#endif
}

void us_mfa::handle_ipv6(int dev, uint8_t *buf, uint16_t len) {
	ip6_hdr *hdr = (ip6_hdr *)buf;

	if (len < sizeof(ip6_hdr))
		return;

	if (hdr->ip6_hlim <= 1)
		return;

	if (!IN6_IS_ADDR_MULTICAST(&hdr->ip6_dst))
		return;

	if (IN6_IS_ADDR_MULTICAST(&hdr->ip6_src) ||
		IN6_IS_ADDR_UNSPECIFIED(&hdr->ip6_src) ||
		IN6_IS_ADDR_LINKLOCAL(&hdr->ip6_src))
		return;

	/*
	 * Silently drop packets with scope reserved, interface-local or link-local.

	 * RFC 4291, Section 2.7.
	 * Nodes must not originate a packet to a multicast address whose scope
	 * field contains the reserved value 0; if such a packet is received, it
	 * must be silently dropped.
	 */
	if ((hdr->ip6_dst.s6_addr[1] & 0xc) == 0)
		return;

	/* Do we have a Hop by Hop header? */
	if (hdr->ip6_nxt == 0) {
		int spaceLeft = (((const ip6_ext *)(hdr + 1))->ip6e_len + 1) * 8;

		if (len < (sizeof(ip6_hdr) + spaceLeft))
			return;

		const uint8_t *ptr = buf + sizeof(ip6_hdr) + 2;

		while (spaceLeft > 0) {
			if (ptr[0] == 0) {
				/* Pad1 */
				spaceLeft--;
			} else {
				spaceLeft -= ptr[1] + 2;
				if (spaceLeft < 0) {
					/* Badly encoded HbH, discard packet */
					return;
				}

				if (ptr[0] != 1) {
					/* not PadN, check top-order 2 bits */

					switch (ptr[0] >> 6) {
					case 0:
						// skip option
						break;

					case 1:
						// discard packet
						return;

					case 2:
					case 3:
						// We handle 2 same as 3 as all of our destinations are
						// multicast

						// XXX send icmp parameter problem, code 2 to the source

						return;
					}
				}
			}
		}
	}

	/* Prepare the packet to be forwarded, decrementing the hop limit. */
	hdr->ip6_hlim--;

	us_mfa_group *grp = match_group(hdr->ip6_dst);

	if (grp) {
		grp->route(dev, hdr, len);
	} else {
		discovered_source(dev, hdr->ip6_dst, hdr->ip6_src);
	}
}

void us_mfa::forward(interface *intf, ip6_hdr *hdr, uint16_t len) const {
	if (len > intf->mtu()) {
		send_icmpv6_toobig(intf, hdr, len);
		return;
	}

	sockaddr_ll sa;

	memset(&sa, 0, sizeof(sa));

	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_IPV6);
	sa.sll_ifindex = intf->index();
	sa.sll_halen = 6;

	// construct the destination ethernet mac address (per rfc2464)
	sa.sll_addr[0] = 0x33;
	sa.sll_addr[1] = 0x33;
	memcpy(sa.sll_addr + 2, hdr->ip6_dst.s6_addr + 12, 4);

	if (::sendto(m_rawsock.fd(), hdr, len, 0,
			(const sockaddr *)&sa, sizeof(sa)) < 0) {
		if (errno == ENETDOWN)
			g_mrd->remove_interface(intf);
		else
			log_failed_packet(intf, len);
	} else {
		// send was OK
		// update our statistics
		// mif_stat_bytes_sent += pktb.rlength;
		// mif_stat_pkt_sent++;
	}
}

void us_mfa::log_failed_packet(const interface *intf, int len) const {
	if (should_log(DEBUG)) {
		log().xprintf("Sending %u bytes via %s failed: %s\n",
			      (uint32_t)len, intf->name(), strerror(errno));
	}
}

void us_mfa::send_icmpv6_toobig(interface *intf, ip6_hdr *hdr, uint16_t len) const {
	const in6_addr *src = &hdr->ip6_src;

	if (IN6_IS_ADDR_UNSPECIFIED(src) || IN6_IS_ADDR_MULTICAST(src))
		return;

	sockaddr_in6 dstaddr;
	memset(&dstaddr, 0, sizeof(dstaddr));
	dstaddr.sin6_family = AF_INET6;
	dstaddr.sin6_addr = *src;

	uint8_t buffer[1280];

	icmp6_hdr *icmphdr = (icmp6_hdr *)buffer;
	icmphdr->icmp6_type = ICMP6_PACKET_TOO_BIG;
	icmphdr->icmp6_code = 0;
	icmphdr->icmp6_cksum = 0;
	icmphdr->icmp6_mtu = htonl(intf->mtu());

	int max = 1280 - sizeof(ip6_hdr) - sizeof(icmp6_hdr);

	int howmuch = len > max ? max : len;

	memcpy(buffer + sizeof(icmp6_hdr), hdr, howmuch);

	if (!g_mrd->icmp().send_icmp(intf, *src, icmphdr,
				     howmuch + sizeof(icmp6_hdr))) {
		if (should_log(EXTRADEBUG)) {
			log().xprintf("Packet too big to %{addr}, dropping.\n",
				      *src);
		}
	}
}

void us_mfa::added_interface(interface *intf) {
	if (intf->is_virtual())
		return;

	packet_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	mreq.mr_ifindex = intf->index();
	mreq.mr_type = PACKET_MR_ALLMULTI;

	if (setsockopt(m_rawsock.fd(), SOL_PACKET, PACKET_ADD_MEMBERSHIP,
					&mreq, sizeof(mreq)) < 0) {
		if (should_log(WARNING)) {
			log().xprintf("Failed to set ALLMULTI on %s, may "
				      "miss packets on this interface.\n",
				      intf->name());
		}
	}
}

void us_mfa::removed_interface(interface *intf) {
	if (intf->is_virtual())
		return;

	packet_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	mreq.mr_ifindex = intf->index();
	mreq.mr_type = PACKET_MR_ALLMULTI;
	setsockopt(m_rawsock.fd(), SOL_PACKET, PACKET_DROP_MEMBERSHIP,
					&mreq, sizeof(mreq));

	/* some bad boys may have left us pending state, clean it */
	for (groups::iterator k = m_groups.begin(); k != m_groups.end(); ++k) {
		k->second->clear_interface_references(k->first, intf);
	}
}

bool us_mfa::output_info(base_stream &out, bool counters, bool noempty) const {
	for (groups::const_iterator i = m_groups.begin();
				i != m_groups.end(); ++i) {
		out.xprintf("Group %{Addr} (%s)\n", i->first, i->second->owner()->name());
		out.inc_level();
		i->second->output_info(out, counters, noempty);
		out.dec_level();
	}

	return true;
}

bool us_mfa::output_info(base_stream &out, const std::vector<std::string> &args) const {
	bool counters = false;
	bool noempty = false;

	if (!args.empty()) {
		if (args[0] == "counters") {
			counters = true;
			if (args.size() > 1) {
				if (args[1] == "no-empty")
					noempty = true;
				else
					return false;
			}
		} else if (args[0] == "dataplane-source-cache") {
			m_sourcedisc.dump_cache(out);
			return true;
		} else {
			return false;
		}
	}

	return output_info(out, counters, noempty);
}


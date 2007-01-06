/*
 * Multicast Routing Daemon (MRD)
 *   linux/linux_icmp_raw.cpp
 *
 * Copyright (C) 2004, 2005, 2006
 *  Universidade de Aveiro, Instituto Telecomunicacoes - Polo Aveiro
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
 * Author:  Hugo Santos <hsantos@av.it.pt>
 */

#include <mrd/mrd.h>
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/group.h>

#include <errno.h>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <sys/ioctl.h>

#include <mrdpriv/linux/icmp_raw.h>

struct ip6_rta {
	uint8_t type;
	uint8_t length;
	uint16_t value;
} __attribute__ ((packed));

/* Not all systems include the IPv6 definitions */
struct _ip6_ext {
	uint8_t ip6e_nxt;
	uint8_t ip6e_len;
};

linux_icmp_raw::linux_icmp_raw()
	: m_rawicmpsock("icmpv6 (raw)", this,
			std::mem_fun(&linux_icmp_raw::data_available)) {
}

static uint8_t ibuffer[8192];

bool linux_icmp_raw::check_startup() {
	if (!icmp_inet6::check_startup())
		return false;

	/* we don't need the INET6 sock to receive */

	::shutdown(m_icmpsock.fd(), SHUT_RD);
	m_icmpsock.unregister(false);

	/* Linux bridges consume the packets before they reach the
	 * protocol handlers leaving us without signaling */
	bool bridges = g_mrd->get_property_bool("handle-proper-bridge");

	int sock = socket(PF_PACKET, SOCK_DGRAM,
			  htons(bridges ? ETH_P_ALL : ETH_P_IPV6));

	if (sock < 0)
		return false;

	m_rawicmpsock.register_fd(sock);

	return true;
}

void linux_icmp_raw::shutdown() {
	m_rawicmpsock.unregister();

	icmp_inet6::shutdown();
}

void linux_icmp_raw::data_available(uint32_t) {
	sockaddr_ll sa;
	socklen_t salen = sizeof(sa);

	int recvlen = recvfrom(m_rawicmpsock.fd(), ibuffer, sizeof(ibuffer),
			       0, (sockaddr *)&sa, &salen);

	if (recvlen < 0 || sa.sll_protocol != htons(ETH_P_IPV6))
		return;

	if (sa.sll_pkttype == PACKET_OUTGOING)
		return;

	ip6_hdr *hdr = (ip6_hdr *)ibuffer;

	uint8_t nxt = hdr->ip6_nxt;
	_ip6_ext *ext = (_ip6_ext *)(ibuffer + sizeof(ip6_hdr));

	int pointer = sizeof(ip6_hdr);

	bool has_mld_rta = false;

	while (pointer < recvlen && nxt != IPPROTO_ICMPV6) {
		if (nxt == IPPROTO_HOPOPTS) {
			uint8_t *ptr = ibuffer + pointer + 2;
			uint8_t *endptr = ibuffer + pointer + (ext->ip6e_len + 1) * 8;
			while (ptr < endptr) {
				ip6_rta *rta = (ip6_rta *)ptr;
				if (rta->type == 5) {
					if (rta->length == 2 && rta->value == 0)
						has_mld_rta = true;
				}
				ptr = ptr + rta->length + 2;
			}
		}

		nxt = ext->ip6e_nxt;
		pointer += (ext->ip6e_len + 1) * 8;
		ext = (_ip6_ext *)(ibuffer + pointer);
	}

	if (nxt != IPPROTO_ICMPV6 || !has_mld_rta)
		return;

	if (g_mrd->should_log(MESSAGE_SIG)) {
		g_mrd->log().xprintf("[ICMPv6] Message from %{addr} to "
			     "%{addr} dev %i\n", hdr->ip6_src, hdr->ip6_dst,
			     (int)sa.sll_ifindex);
	}

	icmp6_hdr *icmphdr = (icmp6_hdr *)ext;
	uint16_t chksum = icmphdr->icmp6_cksum;
	icmphdr->icmp6_cksum = 0;

	if (ipv6_checksum(IPPROTO_ICMPV6, hdr->ip6_src, hdr->ip6_dst, icmphdr,
				recvlen - pointer) != chksum) {
		if (g_mrd->should_log(MESSAGE_ERR)) {
			g_mrd->log().xprintf("[ICMPv6] Bad checksum on "
				     "ICMPv6 message from %{addr}, dropping.\n",
				     hdr->ip6_src);
		}
	} else {
		interface *intf = g_mrd->get_interface_by_index(sa.sll_ifindex);
		if (!intf)
			return;

		icmp_message_available(intf, hdr->ip6_src, hdr->ip6_dst,
				       icmphdr, recvlen - pointer);
	}
}

void linux_icmp_raw::added_interface(interface *intf) {
	packet_mreq mreq;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = intf->index();
	mreq.mr_type = PACKET_MR_ALLMULTI;

	if (setsockopt(m_rawicmpsock.fd(), SOL_PACKET, PACKET_ADD_MEMBERSHIP,
				&mreq, sizeof(mreq)) < 0) {
		if (g_mrd->should_log(VERBOSE)) {
			g_mrd->log().xprintf("[ICMPv6] Will not be able to"
				     " listen to ICMPv6 messages in %s (%i),"
				     " reported error was %s.\n", intf->name(),
				     intf->index(), strerror(errno));
		}
	}
}

void linux_icmp_raw::removed_interface(interface *intf) {
	packet_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	mreq.mr_ifindex = intf->index();
	mreq.mr_type = PACKET_MR_ALLMULTI;

	setsockopt(m_rawicmpsock.fd(), SOL_PACKET, PACKET_DROP_MEMBERSHIP,
			&mreq, sizeof(mreq));
}

void linux_icmp_raw::registration_changed() {
}

void linux_icmp_raw::internal_require_mgroup(const in6_addr &, bool) {
	/* XXX only join specific L2 mcast groups */
}


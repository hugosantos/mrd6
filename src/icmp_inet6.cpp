/*
 * Multicast Routing Daemon (MRD)
 *   icmp_inet6.cpp
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
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/group.h>

#include <mrdpriv/icmp_inet6.h>

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

/* this should be in <netinet/ip6.h> */
#ifndef IP6OPT_ROUTER_ALERT
#define IP6OPT_ROUTER_ALERT 5
#endif

icmp_inet6::icmp_inet6()
	: m_icmpsock("icmpv6", this, std::mem_fun(&icmp_inet6::data_available)) {
}

static uint8_t buffer[8192];

bool icmp_inet6::check_startup() {
	int sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock < 0) {
		if (g_mrd->should_log(WARNING))
			g_mrd->log().perror("ICMPv6: Failed to create ICMPv6 socket");
		return false;
	}

	if (!m_icmpsock.register_fd(sock)) {
		close(sock);
		return false;
	}

	if (!m_icmpsock.enable_mc_loop(false))
		return false;

	return true;
}

void icmp_inet6::shutdown() {
	m_icmpsock.unregister();
}

bool icmp_inet6::apply_icmp_filter() {
#ifdef ICMP6_FILTER
	icmp6_filter filter;
	ICMP6_FILTER_SETBLOCKALL(&filter);

	for (handlers::const_iterator i =
		m_handlers.begin(); i != m_handlers.end(); ++i) {
		ICMP6_FILTER_SETPASS(i->first, &filter);
	}

	if (setsockopt(m_icmpsock.fd(), IPPROTO_ICMPV6, ICMP6_FILTER,
				&filter, sizeof(filter)) < 0) {
		if (g_mrd->should_log(VERBOSE))
			g_mrd->log().writeline("[ICMPv6] failed to install "
					       "ICMP filter in socket.");

		return false;
	}
#endif

	return true;
}

void icmp_inet6::registration_changed() {
	apply_icmp_filter();
}

void icmp_inet6::data_available(uint32_t) {
	int recvlen = m_icmpsock.recvfrom(buffer, sizeof(buffer));

	if (recvlen < 0)
		return;

	sockaddr_in6 dst;
	int index;

	if (!m_icmpsock.destination_address(dst, index))
		return;

	if (index == 0)
		return;

	const sockaddr_in6 &from = m_icmpsock.source_address();

	if (g_mrd->should_log(MESSAGE_SIG))
		g_mrd->log().xprintf("[ICMPv6] Message from %{addr} to %{addr}"
				     " dev %i.\n", from.sin6_addr,
				     dst.sin6_addr, index);

	interface *intf = g_mrd->get_interface_by_index(index);
	if (!intf)
		return;

	icmp_message_available(intf, from.sin6_addr, dst.sin6_addr,
			       (icmp6_hdr *)buffer, recvlen);
}

static int _add_rta(const socket6_base &b, uint16_t value) {
	/* Hop-by-hop Option header with RTA
	 * [ 00 00 05 02 00 00 01 00 ] */
	const int opt_rta_len = 8;

	cmsghdr *cmsg = b.next_cmsghdr(opt_rta_len);
	if (cmsg == NULL)
		return -1;

	cmsg->cmsg_len = CMSG_SPACE(opt_rta_len);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPOPTS;

	uint8_t *extbuf = (uint8_t *)CMSG_DATA(cmsg);

	extbuf[0] = 0x00; /* next header */
	extbuf[1] = 0x00; /* length (8 bytes) */
	extbuf[2] = IP6OPT_ROUTER_ALERT;
	extbuf[3] = 0x02; /* RTA length (2 bytes) */
	*(uint16_t *)(extbuf + 4) = htons(value);
	extbuf[6] = IP6OPT_PADN;
	extbuf[7] = 0x00;

	return CMSG_SPACE(opt_rta_len);
}

bool icmp_inet6::send_icmp(const interface *intf, const in6_addr &src,
			   const in6_addr &to, int rtaval, icmp6_hdr *hdr,
			   uint16_t len) const {
	sockaddr_in6 dst, from;

	memset(&dst, 0, sizeof(sockaddr_in6));
	memset(&from, 0, sizeof(sockaddr_in6));

	dst.sin6_family = AF_INET6;
	dst.sin6_addr = to;

	from.sin6_family = AF_INET6;
	from.sin6_addr = src;

	if (IN6_IS_ADDR_LINKLOCAL(&src))
		from.sin6_scope_id = intf->index();

	int optspace = 0;

	if (rtaval >= 0) {
		optspace = _add_rta(m_icmpsock, rtaval);
		if (optspace < 0) {
			if (g_mrd->should_log(EXTRADEBUG))
				g_mrd->log().writeline(
					"Failed to send ICMPv6 message: wasn't"
					"able to construct message.");
			return false;
		}
	}

	if (m_icmpsock.sendto(hdr, len, &dst, &from, optspace) < 0) {
		if (g_mrd->should_log(EXTRADEBUG))
			g_mrd->log().xprintf("Failed to send ICMPv6 message from"
					     " %{addr} to %{addr}: %s.\n", src,
					     to, strerror(errno));
		return false;
	}

	if (g_mrd->should_log(MESSAGE_SIG))
		g_mrd->log().xprintf("Sent ICMPv6 message from %{addr} to "
				     "%{addr} in %s.\n", src, to,
				     intf->name());

	return true;
}

void icmp_inet6::internal_require_mgroup(const in6_addr &mgroup, bool include) {
	mrd::interface_list::const_iterator i = g_mrd->intflist().begin();

	for (; i != g_mrd->intflist().end(); ++i) {
		if (!i->second->up())
			continue;

		if (include)
			m_icmpsock.join_mc(i->second, mgroup);
		else
			m_icmpsock.leave_mc(i->second, mgroup);
	}
}

void icmp_inet6::added_interface(interface *intf) {
	for (mgroups::const_iterator i =
		m_mgroups.begin(); i != m_mgroups.end(); ++i) {
		m_icmpsock.join_mc(intf, i->first);
	}
}

void icmp_inet6::removed_interface(interface *intf) {
	for (mgroups::const_iterator i =
		m_mgroups.begin(); i != m_mgroups.end(); ++i) {
		m_icmpsock.leave_mc(intf, i->first);
	}
}


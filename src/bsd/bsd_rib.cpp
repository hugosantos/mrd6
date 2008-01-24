/*
 * Multicast Routing Daemon (MRD)
 *   bsd/rib.cpp
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

#include <mrdpriv/bsd/rib.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <unistd.h>
#include <errno.h>

bsd_rib::bsd_rib()
	: evsock("rib events", this, std::mem_fun(&bsd_rib::data_pending)) {

	rtseq = mrd::get_randu32();
}

bool bsd_rib::check_startup() {
	if (!rib_def::check_startup())
		return false;

	int sock = socket(PF_ROUTE, SOCK_RAW, 0);
	if (sock < 0) {
		shutdown();
		return false;
	}

	evsock.register_fd(sock);

	return true;
}

void bsd_rib::check_initial_interfaces() {
	while (1) {
		int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };
		size_t needed;

		if (sysctl(mib, 6, 0, &needed, 0, 0) < 0) {
			return;
		}

		uint8_t *buf = new uint8_t[needed];
		if (!buf) {
			return;
		}

		if (sysctl(mib, 6, buf, &needed, 0, 0) < 0) {
			if (errno == ENOMEM) {
				delete buf;
				continue;
			}
		}

		process_messages((rt_msghdr *)buf, needed);

		delete buf;

		break;
	}
}

void bsd_rib::shutdown() {
	evsock.unregister();
}

static uint8_t buffer[1024];

#ifdef _NETBSD_SOURCE
#define _RT_PAD(x)	((x) > 0 ? (1 + (((x) - 1) | (sizeof(long) - 1))) : sizeof(long))
#else
#define _RT_PAD(x)	(x)
#endif

static void transform(uint8_t *ptr, uint8_t *end, rt_addrinfo *rtinfo) {
#if 0
	cerr << "addrs: " << hex << rtinfo->rti_addrs << endl;

	for (int j = 0; j < (end - ptr); j++) {
		cerr << hex << setw(2) << (int)ptr[j] << " ";
		if ((j % 16) == 15)
			cerr << endl;
	}
	cerr << dec << endl;
#endif

	for (int i = 0; (i < RTAX_MAX) && (ptr < end); i++) {
		if ((rtinfo->rti_addrs & (1 << i)) == 0)
			continue;
		rtinfo->rti_info[i] = (sockaddr *)ptr;
		ptr += _RT_PAD(rtinfo->rti_info[i]->sa_len);
	}
}

static void fix_ll(sockaddr_in6 &addr) {
	if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr)) {
		addr.sin6_scope_id = *((uint16_t *)&addr.sin6_addr.s6_addr[2]);
		*((uint16_t *)&addr.sin6_addr.s6_addr[2]) = 0;
	}
}

static int countprefix(in6_addr *addr) {
	uint8_t *ptr = (uint8_t *)addr;
	int i;

	for (i = 0; i < 16; i++) {
		if (ptr[i] != 0xff)
			break;
	}

	if (i == 16)
		return 128;
	else if (ptr[i] == 0)
		return i * 8;

	uint8_t m = ptr[i];

	while ((m & 0x1) == 0)
		m >>= 1;

	return i * 8 + m;
}

bool bsd_rib::lookup_prefix(const in6_addr &dst, lookup_result &res) const {
	if (evsock.fd() < 0)
		return false;

	rt_msghdr *hdr = (rt_msghdr *)buffer;

	hdr->rtm_type = RTM_GET;
	hdr->rtm_flags = RTF_STATIC | RTF_UP | RTF_GATEWAY;
	hdr->rtm_version = RTM_VERSION;
	hdr->rtm_seq = ++rtseq;
	hdr->rtm_addrs = RTA_DST;

	memset(&hdr->rtm_rmx, 0, sizeof(hdr->rtm_rmx));

	hdr->rtm_inits = 0;

	sockaddr *sa = (sockaddr *)(buffer + sizeof(rt_msghdr));

	memset(sa, 0, sizeof(sockaddr_in6));

	sa->sa_family = AF_INET6;
	sa->sa_len = sizeof(sockaddr_in6);
	((sockaddr_in6 *)sa)->sin6_addr = dst;

	sa = (sockaddr *)(buffer + sizeof(rt_msghdr) + sizeof(sockaddr_in6));
	memset(sa, 0, sizeof(sockaddr_dl));
	sa->sa_family = AF_LINK;
	sa->sa_len = sizeof(sockaddr_dl);
	hdr->rtm_addrs |= RTA_IFP;

	hdr->rtm_msglen = sizeof(rt_msghdr) + sizeof(sockaddr_in6) + sizeof(sockaddr_dl);

	if (write(evsock.fd(), hdr, hdr->rtm_msglen) < 0) {
		if (g_mrd->should_log(WARNING))
			g_mrd->log().perror("(BSD-RIB) Failed while writing to route socket");
		return 0;
	}

	hdr = read_until(rtseq);
	if (!hdr)
		return false;

	return fill_lookup_result(res, hdr);
}

bool bsd_rib::fill_lookup_result(lookup_result &res, rt_msghdr *hdr) const {
	int length = hdr->rtm_msglen;

	rt_addrinfo ai;
	memset(&ai, 0, sizeof(ai));
	ai.rti_addrs = hdr->rtm_addrs;

	transform((uint8_t *)(hdr + 1), ((uint8_t *)hdr) + length, &ai);

	if (ai.rti_info[RTAX_DST]
		&& ai.rti_info[RTAX_GATEWAY]) {

		res.dev = hdr->rtm_index;

		int prefixlen = 128;
		if (ai.rti_info[RTAX_NETMASK] && ai.rti_info[RTAX_NETMASK]->sa_len)
			prefixlen = countprefix(&((sockaddr_in6 *)ai.rti_info[RTAX_NETMASK])->sin6_addr);

		if (ai.rti_info[RTAX_GATEWAY]->sa_family == AF_INET6)
			res.nexthop = ((sockaddr_in6 *)ai.rti_info[RTAX_GATEWAY])->sin6_addr;
		else
			res.nexthop = in6addr_any;

		/* XXX todo */
		res.source = in6addr_any;

		res.dst = inet6_addr(((sockaddr_in6 *)ai.rti_info[RTAX_DST])->sin6_addr, prefixlen);

		return true;
	}

	return false;
}

void bsd_rib::process_messages(rt_msghdr *hdr, int len) {
	uint8_t *ptr = (uint8_t *)hdr;
	uint8_t *end = ptr + len;

	while (ptr < end) {
		if_msghdr *ifm = (if_msghdr *)ptr;
		ifa_msghdr *ifam = 0;

		if (ifm->ifm_type != RTM_IFINFO) {
			return;
		}

		ptr += ifm->ifm_msglen;

		int count = 0;

		while (ptr < end) {
			ifa_msghdr *currifam = (ifa_msghdr *)ptr;
			if (currifam->ifam_type != RTM_NEWADDR)
				break;
			if (ifam == 0)
				ifam = currifam;
			ptr += currifam->ifam_msglen;
			count++;
		}

		process_if_msg(ifm);

		while (count > 0) {
			process_ifa_msg(ifm->ifm_index, ifam, true);
			ifam = (ifa_msghdr *)((uint8_t *)ifam + ifam->ifam_msglen);
			count--;
		}
	}
}

static int _conv_intf(int type) {
	if (type == IFT_ETHER)
		return interface::Ethernet;
	else if (type == IFT_PPP)
		return interface::PPP;
	else if (type == IFT_IEEE1394)
		return interface::IEEE1394;
	else if (type == IFT_L2VLAN)
		return interface::IEEE802_1Q;
	return interface::None;
}

void bsd_rib::process_if_msg(if_msghdr *hdr) {
	char name[IFNAMSIZ];

	const char *pname = if_indextoname(hdr->ifm_index, name);
	if (!pname)
		return;

	interface *intf =
		g_mrd->found_interface(hdr->ifm_index, pname,
			_conv_intf(hdr->ifm_data.ifi_type), hdr->ifm_data.ifi_mtu,
			hdr->ifm_flags);

	if (intf) {
		if (hdr->ifm_flags & IFF_UP)
			intf->change_state(interface::Up);
		else
			intf->change_state(interface::Down);
	}
}

void bsd_rib::process_ifa_msg(int index, ifa_msghdr *ifam, bool added) {
	rt_addrinfo ai;
	memset(&ai, 0, sizeof(ai));

	ai.rti_addrs = ifam->ifam_addrs;

	transform((uint8_t *)(ifam + 1), ((uint8_t *)ifam) + ifam->ifam_msglen, &ai);

	ifam = (ifa_msghdr *)((uint8_t *)ifam + ifam->ifam_msglen);

	process_addrinfo(index, &ai, added);
}

void bsd_rib::process_addrinfo(int index, rt_addrinfo *rti, bool added) {
	if (!rti->rti_info[RTAX_IFA])
		return;

	interface *intf = g_mrd->get_interface_by_index(index);
	if (!intf)
		return;

	if (rti->rti_info[RTAX_IFA]->sa_family == AF_INET6) {
		int prefixlen = 128;

		if (rti->rti_info[RTAX_NETMASK]) {
			prefixlen = countprefix(&((sockaddr_in6 *)rti->rti_info[RTAX_NETMASK])->sin6_addr);
		}

		sockaddr_in6 *sin6 = (sockaddr_in6 *)rti->rti_info[RTAX_IFA];

		fix_ll(*sin6);

		inet6_addr addr(sin6->sin6_addr, prefixlen);

		intf->address_added_or_removed(added, addr);
	}
}

void bsd_rib::data_pending(uint32_t) {
	int l = read(evsock.fd(), buffer, sizeof(buffer));
	if (l < 0)
		return;

	int ptr = 0;
	for (rt_msghdr *hdr1 = (rt_msghdr *)buffer; ptr < l;
			ptr += hdr1->rtm_msglen, hdr1 = (rt_msghdr *)(buffer + ptr)) {
		event_pending(hdr1);
	}
}

static const char *_rtmsg_type_name(int type) {
	switch (type) {
	case RTM_ADD:
		return "ADD";
	case RTM_DELETE:
		return "DELETE";
	case RTM_CHANGE:
		return "CHANGE";
	case RTM_GET:
		return "GET";
	case RTM_LOSING:
		return "LOSING";
	case RTM_REDIRECT:
		return "REDIRECT";
	case RTM_MISS:
		return "MISS";
	case RTM_LOCK:
		return "LOCK";
	case RTM_RESOLVE:
		return "RESOLVE";
	case RTM_NEWADDR:
		return "NEWADDR";
	case RTM_DELADDR:
		return "DELADDR";
	case RTM_IFINFO:
		return "IFINFO";
#ifdef RTM_IFANNOUNCE
	case RTM_IFANNOUNCE:
		return "IFANNOUNCE";
#endif
#ifdef RTM_NEWMADDR
	case RTM_NEWMADDR:
		return "NEWMADDR";
	case RTM_DELMADDR:
		return "DELMADDR";
#endif
	default:
		return "UNKNOWN";
	}
}

void bsd_rib::event_pending(rt_msghdr *rtm) {
	union {
		rt_msghdr *rt;
		if_msghdr *ifm;
		ifa_msghdr *ifam;
#ifdef RTM_IFANNOUNCE
		if_announcemsghdr *ann;
#endif
	} u;

	u.rt = rtm;

	if (g_mrd->should_log(EXTRADEBUG)) {
		g_mrd->log().xprintf("(BSD-RIB) Pending event type %s\n",
				     _rtmsg_type_name(u.rt->rtm_type));
	}

	switch (u.rt->rtm_type) {
	case RTM_ADD:
	case RTM_DELETE:
	case RTM_CHANGE:
		{
			lookup_result res;
			if (fill_lookup_result(res, u.rt))
				prefix_changed(u.rt->rtm_type != RTM_DELETE, res);
		}
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		process_ifa_msg(u.ifam->ifam_index, u.ifam,
				u.rt->rtm_type == RTM_NEWADDR);
		break;
	case RTM_IFINFO:
		process_if_msg(u.ifm);
		break;
#ifdef RTM_IFANNOUNCE
	case RTM_IFANNOUNCE:
		if (u.ann->ifan_what == IFAN_DEPARTURE) {
			interface *intf = g_mrd->get_interface_by_name(u.ann->ifan_name);
			if (intf) {
				g_mrd->lost_interface(intf->index());
			}
		}
		break;
#endif
	default:
		/* nothing */
		break;
	}
}

rt_msghdr *bsd_rib::read_until(unsigned seq) const {
	rt_msghdr *hdr = (rt_msghdr *)buffer;

	while (1) {
		int l = read(evsock.fd(), buffer, sizeof(buffer));
		if (l < 0)
			return 0;

		int ptr = 0;
		for (rt_msghdr *hdr1 = hdr; ptr < l; ptr += hdr1->rtm_msglen,
						     hdr1 = (rt_msghdr *)(buffer + ptr)) {
			if ((uint32_t)hdr1->rtm_seq == seq && hdr1->rtm_pid == getpid()) {
				return hdr1;
			} else {
				const_cast<bsd_rib *>(this)->event_pending(hdr1);
			}
		}
	}

	return 0;
}


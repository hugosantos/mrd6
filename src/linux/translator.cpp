/*
 * Multicast Routing Daemon (MRD)
 *   translator.cpp - IPv4 to IPv6 multicast translator
 *
 * Copyright (C) 2009, 2010 - Teemu Kiviniemi
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
 * Author:  Teemu Kiviniemi <firstname.lastname@iki.fi>
 */

#include <mrdpriv/linux/translator.h>

#include <mrd/mrd.h>
#include <mrd/interface.h>
#include <mrd/group.h>
#include <mrdpriv/linux/us_mfa.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if.h>

translator::translator(us_mfa *mfa)
	: node(g_mrd, "translator"),
	m_igmp_fd(-1),
	m_enabled(false),
	m_fragment_id(0),
	m_rawsock("translator raw sock", this,
		  std::mem_fun(&translator::data_available)),
	m_mfa(mfa) {

	m_p_ipv4_interface = instantiate_property_s("ipv4-interface", "");
	m_p_ipv4_address = instantiate_property_s("ipv4-address", "");
	m_p_unicast_prefix = instantiate_property_a("unicast-prefix", inet6_addr::any());
	m_p_asm_prefix = instantiate_property_a("asm-prefix", inet6_addr::any());
	m_p_ssm_prefix = instantiate_property_a("ssm-prefix", inet6_addr::any());
}

translator::~translator() {
}


/* Pre-initialization */
bool translator::pre_startup() {
	if (!node::check_startup())
		return false;

	if (!m_p_ipv4_interface ||
	    !m_p_ipv4_address ||
	    !m_p_unicast_prefix ||
	    !m_p_asm_prefix ||
	    !m_p_ssm_prefix) {
		return false;
	}

	g_mrd->add_child(this);

	return true;
}

/* Initialization */
bool translator::check_startup() {

	m_enabled = false;

	if (strlen(m_p_ipv4_interface->get_string()) == 0) {
		/* Translator is disabled. */
		return true;
	}

	/* Check prefixes */
	if (m_p_unicast_prefix->get_address().prefixlen != 96 ||
	    m_p_asm_prefix->get_address().prefixlen != 96 ||
	    m_p_ssm_prefix->get_address().prefixlen != 96) {
		should_log(FATAL);
		log().writeline("Translator: length of translator prefixes must be /96.");
		return false;
	}
	if (!IN6_IS_ADDR_MULTICAST(m_p_asm_prefix->get_address().address_p()) ||
	    !IN6_IS_ADDR_MULTICAST(m_p_ssm_prefix->get_address().address_p())) {
		should_log(FATAL);
		log().writeline("Translator: ASM/SSM prefixes must be valid multicast prefixes.");
		return false;
	}

	/* Lookup interface */
	m_interface = g_mrd->get_interface_by_name(m_p_ipv4_interface->get_string());
	if (!m_interface) {
		should_log(FATAL);
		log().xprintf("Translator: interface %s does not exist.\n",
				m_p_ipv4_interface->get_string());
		return false;
	}

	/* Create a virtual network interface. */
	m_virtual_interface = g_mrd->found_interface((1 << 30),
			"VirtualIPv4",
			interface::IPv4_Translator,
			m_interface->mtu(),
			IFF_UP | IFF_BROADCAST | IFF_NOARP | IFF_ALLMULTI | IFF_MULTICAST | IFF_LOWER_UP);
	if (!m_virtual_interface) {
		should_log(FATAL);
		log().writeline("Translator: Could not create virtual interface.");
		return false;
	}

	/* Add route to unicast prefix via the virtual interface. */
	g_mrd->mrib().local().register_prefix(m_p_unicast_prefix->get_address(), m_virtual_interface);

	/* Add local address to the virtual interface. */
	in_addr virt_addr4;
	if (inet_pton(AF_INET, m_p_ipv4_address->get_string(), &virt_addr4) < 0) {
		should_log(FATAL);
		log().perror("Translator: could not parse ipv4-address");
		return false;
	} else {
		in6_addr virt_addr6 = m_p_unicast_prefix->get_address().address();
		set_embedded_address(virt_addr6, virt_addr4);
		inet6_addr addr(virt_addr6);
	}

	m_virtual_interface->change_state(interface::Up);

	/* Build the IPv6 header templates */
	memset(&m_asm_hdr, 0, sizeof(m_asm_hdr));
	/* Version, Traffic Class, Flow Label */
	m_asm_hdr.ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
	m_asm_hdr.ip6_src = m_p_unicast_prefix->get_address().address();
	m_ssm_hdr = m_asm_hdr;
	m_asm_hdr.ip6_dst = m_p_asm_prefix->get_address().address();
	m_ssm_hdr.ip6_dst = m_p_ssm_prefix->get_address().address();

	/* Set up socket for IGMP */
	m_igmp_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (m_igmp_fd < 0) {
		should_log(FATAL);
		log().perror("Translator: Failed to create UDP socket for IGMP");
		return false;
	}

	/* Raw socket for incoming packets */
	const int raw_fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (raw_fd < 0) {
		should_log(FATAL);
		log().perror("Translator: Failed to create packet socket");
		return false;
	}
	if (fcntl(raw_fd, F_SETFL, O_NONBLOCK) < 0) {
		should_log(FATAL);
		log().perror("Translator: Failed to change packet socket to non-blocking mode");
		return false;
	}

	/* Receive buffer */
	const int val = 256 * 1024;
	setsockopt(raw_fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));

	/* Bind the packet socket to IPv4 interface */
	sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_IP);
	sa.sll_ifindex = m_interface->index();
	if (bind(raw_fd, (sockaddr *) &sa, sizeof(sa)) < 0) {
		should_log(FATAL);
		log().perror("Translator: Failed to bind packet socket");
		return false;
	}

	/* Setup ICMPv6 handler for PACKET_TOO_BIG messages */
	if (!g_mrd->icmp().register_handler(ICMP6_PACKET_TOO_BIG, this))
		return false;

	/* Configure the socket to receive all multicast packets */
	packet_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = m_interface->index();
	mreq.mr_type = PACKET_MR_ALLMULTI;
	if (setsockopt(raw_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq)) < 0) {
		if (should_log(WARNING)) {
			log().xprintf("Translator: Failed to set ALLMULTI on %s, may "
				      "miss packets on this interface.\n",
				      m_interface->name());
		}
	}

	m_rawsock.register_fd(raw_fd);
	m_enabled = true;

	return true;
}

/* De-initialization */
void translator::shutdown() {
	if (m_igmp_fd >= 0) {
		close(m_igmp_fd);
		m_igmp_fd = -1;
	}
	m_rawsock.unregister();
	m_enabled = false;
}

/* Return node description */
const char *translator::description() const {
	return "IPv4 to IPv6 multicast translator";
}

/* Dump node information */
bool translator::output_info(base_stream &out, const std::vector<std::string> &args) const {

	if (args.size() != 0)
		return false;

	out.xprintf("%s is %s", description(), m_enabled ? "enabled" : "disabled");
	out.newl();

	if (!m_enabled)
		return true;

	out.inc_level();

	out.write("IPv4 interface: ");
	m_p_ipv4_interface->output_value(out);
	out.newl();

	out.write("IPv4 address: ");
	m_p_ipv4_address->output_value(out);
	out.newl();

	out.write("Unicast prefix: ");
	m_p_unicast_prefix->output_value(out);
	out.newl();

	out.write("ASM prefix: ");
	m_p_asm_prefix->output_value(out);
	out.newl();

	out.write("SSM prefix: ");
	m_p_ssm_prefix->output_value(out);
	out.newl();

	out.xprintf("Translated groups: %u\n", (uint32_t) m_group_mtu.size());

	out.dec_level();

	return true;
}

/* Join/leave a new group */
void translator::change_group_state(const in6_addr &grp, bool include) {
	if (!m_enabled)
		return;

	if (!is_asm_group(grp))
		return;

	group_req gr;
	memset(&gr, 0, sizeof(gr));

	sockaddr_in *sa = (sockaddr_in *) &gr.gr_group;
	sa->sin_family = AF_INET;
	sa->sin_addr = get_embedded_address(grp);

	gr.gr_interface = m_interface->index();

	if (should_log(DEBUG)) {
		char grp_str[INET_ADDRSTRLEN];
		if (!inet_ntop(AF_INET, &sa->sin_addr, grp_str, sizeof(grp_str)))
			log().perror("Translator: Can not convert IPv4 address");
		else
			log().xprintf("Translator: %s IPv4 ASM group (*, %s)\n",
				      include ? "Joining" : "Leaving", grp_str);
	}

	if (setsockopt(m_igmp_fd, IPPROTO_IP,
			include ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP,
					&gr, sizeof(gr)) < 0) {
		if (should_log(WARNING)) {
			if (include)
				log().perror("Translator: MCAST_JOIN_GROUP");
			else
				log().perror("Translator: MCAST_LEAVE_GROUP");
		}
	}
}

/* Join/leave an SSM channel */
void translator::change_source_state(const in6_addr &grp, const in6_addr &src, bool include) {
	if (!m_enabled)
		return;

	if (!is_ssm_group(grp))
		return;

	if (!is_valid_source(src))
		return;

	group_source_req gsr;
	memset(&gsr, 0, sizeof(gsr));

	sockaddr_in *grp_sa = (sockaddr_in *) &gsr.gsr_group;
	grp_sa->sin_family = AF_INET;
	grp_sa->sin_addr = get_embedded_address(grp);

	sockaddr_in *src_sa = (sockaddr_in *) &gsr.gsr_source;
	src_sa->sin_family = AF_INET;
	src_sa->sin_addr = get_embedded_address(src);

	gsr.gsr_interface = m_interface->index();

	if (should_log(DEBUG)) {
		char grp_str[INET_ADDRSTRLEN];
		char src_str[INET_ADDRSTRLEN];

		if (!inet_ntop(AF_INET, &grp_sa->sin_addr, grp_str, sizeof(grp_str)))
			log().perror("Translator: Can not convert IPv4 address");
		else if (!inet_ntop(AF_INET, &src_sa->sin_addr, src_str, sizeof(src_str)))
			log().perror("Translator: Can not convert IPv4 address");
		else
			log().xprintf("Translator: %s IPv4 SSM channel (%s, %s).\n",
				      include ? "Joining" : "Leaving", src_str, grp_str);
	}

	if (setsockopt(m_igmp_fd, IPPROTO_IP,
			include ? MCAST_JOIN_SOURCE_GROUP : MCAST_LEAVE_SOURCE_GROUP,
					&gsr, sizeof(gsr)) < 0) {

		if (should_log(WARNING)) {
			if (include)
				log().perror("Translator: MCAST_JOIN_SOURCE_GROUP");
			else
				log().perror("Translator: MCAST_LEAVE_SOURCE_GROUP");
		}
	}

}

/* Handle incoming ICMPv6 messages. */
void translator::icmp_message_available(interface *intf, const in6_addr &src,
					const in6_addr &dst, icmp6_hdr *hdr, int len) {

	if (!m_p_unicast_prefix->get_address().matches(dst))
		return;

	if (len < (int) (sizeof(icmp6_hdr) + sizeof(ip6_hdr)))
		return;

	if (hdr->icmp6_type != ICMP6_PACKET_TOO_BIG)
		return;

	ip6_hdr *ip_hdr = (ip6_hdr *) (((uint8_t *) hdr) + sizeof(icmp6_hdr));

	/* Set new MTU */
	set_mtu(ip_hdr->ip6_dst, ntohl(hdr->icmp6_dataun.icmp6_un_data32[0]));
}

/* MRD event handler */
void translator::event(int event, void *ptr) {
	if (event == mrd::ReleasedGroup) {
		group *grp = (group *) ptr;
		/* Group MTU information no longer needed. */
		erase_mtu(grp->id().address());
	}
}


/* Receive incoming IPv4 packets */
void translator::data_available(uint32_t) {

	sockaddr_ll sa;
	socklen_t salen = sizeof(sa);
	int len;
	while ((len = g_mrd->ipktb->recvfrom(m_rawsock.fd(),
				(sockaddr *)&sa, &salen)) > 0) {

		if (sa.sll_protocol == htons(ETH_P_IP) &&
		    sa.sll_pkttype != PACKET_OUTGOING)
			handle_ipv4(sa.sll_ifindex, g_mrd->ipktb->buffer(), len);

	}
}

/* Handle and translate an incoming IPv4 packet */
void translator::handle_ipv4(const int dev, uint8_t *buf, const uint16_t len) {

	if (len < sizeof(ip))
		return;

	ip *hdr = (ip *) buf;

	const uint16_t ip_len = ntohs(hdr->ip_len);
	if (len < ip_len)
		return;

	if (hdr->ip_v != 4)
		return;

	if (hdr->ip_ttl <= 1)
		return;

	/* Skip IGMP, PIM, ICMP */
	if (hdr->ip_p == IPPROTO_IGMP ||
	    hdr->ip_p == IPPROTO_PIM ||
	    hdr->ip_p == IPPROTO_ICMP)
		return;

	/* Select IPv6 header template */
	ip6_hdr *hdr6;
	if (is_asm_group(hdr->ip_dst))
		hdr6 = &m_asm_hdr;
	else if (is_ssm_group(hdr->ip_dst))
		hdr6 = &m_ssm_hdr;
	else
		return;

	if (!is_valid_source(hdr->ip_src))
		return;

	/* IPv4 header length */
	const uint16_t ip_hl = ((uint16_t) hdr->ip_hl) << 2;
	if (ip_hl > ip_len)
		return;

	/* Check IPv4 header checksum */
	if (ipv4_checksum(buf, ip_hl) != 0) {
		return;
	}

	/* Check header length */
	if (ip_hl < 20) {
		return;
	} else if (ip_hl > 20) {
		/* Header contains extra options */

		/* Too long? */
		if (ip_hl > 60)
			return;

		uint8_t *opt = buf + sizeof(ip);
		uint8_t *opt_end = buf + ip_hl;

		while (opt < opt_end) {
			uint8_t opt_number = *opt;
			if (opt_number == IPOPT_EOL)
				break;
			else if (opt_number == IPOPT_NOP) {
				opt++;
				continue;
			}

			/* Other options are type-length-value */

			/* Option length */
			uint8_t *opt_len_p = opt + IPOPT_OLEN;
			if (opt_len_p >= opt_end)
				return;
			uint8_t opt_len = *opt_len_p;

			/* Source routing */
			if (opt_number == IPOPT_LSRR || opt_number == IPOPT_SSRR) {
				if (opt_len < 3)
					return;

				/* Pointer to next route data entry */
				uint8_t *offset_p = opt + IPOPT_OFFSET;
				if (offset_p >= opt_end)
					return;
				uint8_t offset = *offset_p;

				if (offset < 4 || offset <= opt_len) {
					/* Invalid offset or an unexpired source route.
					 * (RFC 2765 section 3.1.) */
					return;
				}

			}
			opt += opt_len;
		}
	}

	/* IPv4 type of service to IPv6 traffic class */
	hdr6->ip6_ctlun.ip6_un1.ip6_un1_flow =
		(hdr6->ip6_ctlun.ip6_un1.ip6_un1_flow & htonl(0xf00fffff)) |
		htonl(((uint32_t) hdr->ip_tos) << 20);

	/* Next header */
	hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt = hdr->ip_p;
	/* Hop limit */
	hdr6->ip6_ctlun.ip6_un1.ip6_un1_hlim = hdr->ip_ttl;
	/* Addresses */
	set_embedded_address(hdr6->ip6_src, hdr->ip_src);
	set_embedded_address(hdr6->ip6_dst, hdr->ip_dst);

	/* Pointer to packet payload. */
	uint8_t *payload = buf + ip_hl;

	/* Payload length */
	const uint16_t plen = ip_len - ip_hl;

	/* Fragment offset + flags */
	const uint16_t frag_off = ntohs(hdr->ip_off);

	/* First fragment? */
	if ((frag_off & IP_OFFMASK) == 0) {

		if (hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {

			/* Recalculate UDP checksum */

			if (plen < sizeof(udphdr))
				return;
			udphdr *udp_hdr = (udphdr *) payload;

			const uint16_t udp_len = ntohs(udp_hdr->len);

			if (udp_hdr->check == 0) {
				/* Full checksum calculation needed */

				if (udp_len > plen) {
					/* Not a complete packet. Checksum can't be calculated. */
					if (should_log(DEBUG)) {
						log().writeline("Translator: dropping fragmented IPv4 UDP packet with zero checksum.");
					}
					return;
				}

				udp_hdr->check = ipv6_checksum(hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt,
							       hdr6->ip6_src, hdr6->ip6_dst, udp_hdr, udp_len);
			} else {
				/* Calculate a new checksum incrementally: RFC 1624 */

				uint32_t sum = (uint16_t) ~udp_hdr->check;

				/* Remove IPv4 addresses from checksum. */
				sum += (uint16_t) (~hdr->ip_src.s_addr);
				sum += (uint16_t) (~hdr->ip_dst.s_addr);
				sum += (uint16_t) (~hdr->ip_src.s_addr >> 16);
				sum += (uint16_t) (~hdr->ip_dst.s_addr >> 16);

				/* Add IPv6 addresses to checksum. */
				for (int i = 0; i < 8; i++) {
					sum += hdr6->ip6_src.s6_addr16[i];
					sum += hdr6->ip6_dst.s6_addr16[i];
				}

				while (sum >> 16)
					sum = (sum & 0xffff) + (sum >> 16);

				udp_hdr->check = (uint16_t) (~sum);
				if (udp_hdr->check == 0)
					udp_hdr->check = 0xffff;
			}

		}

		// XXX: handle more protocols?
	}

	/* Get MTU for this multicast group */
	const uint16_t mtu = get_mtu(hdr->ip_dst);

	/* Length of IPv6 packet. */
	uint16_t ip6_len = plen + sizeof(ip6_hdr);

	if (ip6_len > mtu ||
	    (frag_off & (IP_OFFMASK | IP_MF)) != 0) {
		/* IPv6 packet too big, or the IPv4 packet is a fragment. */

		/* Increase IPv6 packet length */
		ip6_len += sizeof(ip6_frag);

		/* Move payload pointer backwards. */
		payload -= sizeof(ip6_frag);

		/* Create IPv6 fragment header in the beginning of payload. */
		ip6_frag *frag_hdr = (ip6_frag *) payload;

		/* Identification. */
		if (((frag_off & IP_DF) != 0) && (hdr->ip_id == 0)) {
			/* A packet with DF set contains a zero ID.
			 * The ID may not be valid. Generate a new
			 * ID with the high-order 16 bits always
			 * non-zero. */
			m_fragment_id++;
			if ((m_fragment_id & 0xffff0000) == 0)
				m_fragment_id = 0x00010000;

			frag_hdr->ip6f_ident = htonl(m_fragment_id);
		} else {
			/* Copy identification from IPv4 packet.
			 * High-order 16 bits set to zero. */
			frag_hdr->ip6f_ident = htonl((uint32_t) ntohs(hdr->ip_id));
		}

		/* Next header */
		frag_hdr->ip6f_nxt = hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_FRAGMENT;

		/* Set reserved field to zero. */
		frag_hdr->ip6f_reserved = 0;

		/* Fragment offset. */
		frag_hdr->ip6f_offlg = htons((frag_off & IP_OFFMASK) << 3) & IP6F_OFF_MASK;

		if ((frag_off & IP_MF) != 0) {
			/* Set more fragments flag */
			frag_hdr->ip6f_offlg |= IP6F_MORE_FRAG;
		}

	}

	/* Set payload length. */
	hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(ip6_len - sizeof(ip6_hdr));

	/* Pointer to the correct destination of IPv6 header. */
	uint8_t *buf6 = payload - sizeof(ip6_hdr);

	/* Copy IPv6 header to its correct position */
	memcpy(buf6, hdr6, sizeof(ip6_hdr));

	if (ip6_len > mtu) {
		send_fragmented_ipv6(m_virtual_interface->index(), buf6, plen, mtu);
	} else
		m_mfa->handle_ipv6(m_virtual_interface->index(), buf6, ip6_len);

}

/* Send an IPv6 packet in fragments. buf must contain an IPv6 packet with a fragment header */
void translator::send_fragmented_ipv6(const int dev, uint8_t *buf, uint16_t plen, uint16_t mtu) {

	/* IPv6 header. */
	ip6_hdr *hdr = (ip6_hdr *) buf;

	/* Pointer to fragment header */
	ip6_frag *frag_hdr = (ip6_frag *) (buf + sizeof(ip6_hdr));

	/* Subtract headers from MTU */
	mtu -= (sizeof(ip6_hdr) + sizeof(ip6_frag));

	/* Current fragment offset */
	uint16_t frag_offset = ntohs(frag_hdr->ip6f_offlg & IP6F_OFF_MASK);

	/* Save the value of the more fragments bit */
	const uint16_t frag_mfbit = frag_hdr->ip6f_offlg & IP6F_MORE_FRAG;

	/* Save hop limit */
	const uint8_t hop_limit = hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;

	for (;;) {

		/* Update fragment offset:
		 * Three lowest bits are dropped => Automatically divides by 8. */
		frag_hdr->ip6f_offlg = htons(frag_offset) & IP6F_OFF_MASK;

		/* Length of this fragment */
		uint16_t frag_len = mtu < plen ? mtu : plen;

		if (frag_len != plen) {
			/* Set more fragments bit */
			frag_hdr->ip6f_offlg |= IP6F_MORE_FRAG;

			/* Fragment length must be a multiple of 8. Zero 3 lowest bits */
			frag_len &= 0xfff8;

		} else {
			/* Last fragment: set more fragments bit to the value in original
			 * fragment header. */
			frag_hdr->ip6f_offlg |= frag_mfbit;
		}

		/* Update IPv6 payload length */
		hdr->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(frag_len + sizeof(ip6_frag));

		/* Forward fragment */
		m_mfa->handle_ipv6(dev, buf, frag_len + (sizeof(ip6_hdr) + sizeof(ip6_frag)));

		/* Restore hop limit, as it was modified by handle_ipv6() */
		hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim = hop_limit;

		/* Update remaining payload length */
		plen -= frag_len;

		/* Done? */
		if (plen == 0)
			break;

		/* Update fragment offset */
		frag_offset += frag_len;

		/* Move IPv6 and fragment headers before the new payload section */
		buf += frag_len;
		memmove(buf, hdr, (sizeof(ip6_hdr) + sizeof(ip6_frag)));
		hdr = (ip6_hdr *) buf;
		frag_hdr = (ip6_frag *) (buf + sizeof(ip6_hdr));

	}
}


/* Return true if a group is an IPv4 ASM group */
bool translator::is_asm_group(const in6_addr &grp) const {

	/* Must be within the IPv6 and IPv4 ASM prefixes. */
	return (m_p_asm_prefix->get_address().matches(grp) &&
		is_asm_group(get_embedded_address(grp)));
}

/* Return true if a group is an IPv4 SSM group */
bool translator::is_ssm_group(const in6_addr &grp) const {

	/* Must be within the IPv6 and IPv4 SSM prefixes. */
	return (m_p_ssm_prefix->get_address().matches(grp) &&
		is_ssm_group(get_embedded_address(grp)));
}

/* Return true if a group is an IPv4 ASM group */
bool translator::is_asm_group(const in_addr grp) const {
	/* 0xe0000000 is 224.0.0.0 */
	/* 0xf0000000 is /4 mask */
	if ((ntohl(grp.s_addr) & 0xf0000000) != 0xe0000000)
		return false;

	/* Must not be SSM or link local. */
	if (is_ssm_group(grp) || is_ll_group(grp))
		return false;

	return true;
}

/* Return true if a group is an IPv4 SSM group */
bool translator::is_ssm_group(const in_addr grp) const {
	/* 0xe8000000 is 232.0.0.0 */
	/* 0xff000000 is /8 mask */
	return (ntohl(grp.s_addr) & 0xff000000) == 0xe8000000;
}

/* Return true if a group is an IPv4 link-local multicast group */
bool translator::is_ll_group(const in_addr grp) const {
	/* 0xe0000000 is 224.0.0.0 */
	/* 0xffffff00 is /24 mask */
	return (ntohl(grp.s_addr) & 0xffffff00) == 0xe0000000;
}

/* Return true if an IPv4 source address is valid for multicast. */
bool translator::is_valid_source(const in6_addr &src) const {

	/* Must be valid IPv6 and IPv4 source. */
	return (m_p_unicast_prefix->get_address().matches(src) &&
		is_valid_source(get_embedded_address(src)));
}

/* Return true if an IPv4 source address is valid for multicast. */
bool translator::is_valid_source(const in_addr src) const {
	const in_addr_t h_src = ntohl(src.s_addr);

	/* 127.0.0.0/8 */
	if ((h_src & 0xff000000) == 0x7f000000)
		return false;

	/* 224.0.0.0/4 */
	if ((h_src & 0xf0000000) == 0xe0000000)
		return false;

	return true;
}


/* Return the embedded IPv4 address (last 32 bits) from an IPv6 address. */
in_addr translator::get_embedded_address(const in6_addr &addr6) const {
	in_addr addr4;
	addr4.s_addr = (in_addr_t) addr6.s6_addr32[3];
	return addr4;
}

/* Set the embedded IPv4 address (last 32 bits) of an IPv6 address. */
void translator::set_embedded_address(in6_addr &addr6, const in_addr addr) const {
	addr6.s6_addr32[3] = (uint32_t) addr.s_addr;
}

/* Set new MTU for a destination. */
void translator::set_mtu(const in6_addr &grp, uint32_t mtu) {

	/* Translated group? */
	if (!is_asm_group(grp) &&
	    !is_ssm_group(grp))
		return;

	/* Set MTU only if a group state exists. */
	const inet6_addr addr6(grp);
	if (!g_mrd->get_group_by_addr(addr6))
		return;

	if (mtu < 1280)
		mtu = 1280;
	else {
		const uint32_t max_len = g_mrd->ipktb->bufferlen();
		if (mtu > max_len)
			mtu = max_len;
		if (mtu > 65535)
			mtu = 65535;
	}

	const uint16_t mtu16 = (uint16_t) mtu;
	const in_addr grp4 = get_embedded_address(grp);

	/* Already smaller or equal? */
	if (get_mtu(grp4) <= mtu16)
		return;

	m_group_mtu[grp4.s_addr] = mtu16;
}

/* Get MTU for a destination. */
uint16_t translator::get_mtu(const in_addr grp) const {
	group_mtu_map::const_iterator i = m_group_mtu.find(grp.s_addr);
	if (i == m_group_mtu.end()) {
		const uint32_t bufferlen = g_mrd->ipktb->bufferlen();
		if (bufferlen <= 65535)
			return (uint16_t) bufferlen;
		return 65535;
	}
	return i->second;
}

/* Erase previously set MTU. */
void translator::erase_mtu(const in6_addr &grp) {
	m_group_mtu.erase(get_embedded_address(grp).s_addr);
}

/* Calculate IPv4 checksum (RFC 1071) */
uint16_t translator::ipv4_checksum(const uint8_t *buf, uint16_t len) const {
	uint32_t sum = 0;
	const uint16_t *buf16 = (uint16_t *) buf;

	while (len > 1) {
		sum += *buf16;
		buf16++;
		len -= 2;
	}
	if (len > 0)
		sum += *((uint8_t *) buf16);

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	uint16_t checksum = (uint16_t) (~sum);

	return checksum;
}

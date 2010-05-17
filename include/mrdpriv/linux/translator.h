/*
 * Multicast Routing Daemon (MRD)
 *   translator.h - IPv4 to IPv6 multicast translator
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

#ifndef _mrd_translator_h_
#define _mrd_translator_h_

#include <mrd/mrd.h>
#include <mrd/node.h>
#include <mrd/icmp.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <map>

class interface;
class us_mfa;

/*!
 * IPv4 to IPv6 multicast translator
 */
class translator : public node, public icmp_handler {
public:

	translator(us_mfa *);
	~translator();

	/* Pre-initialization */
	bool pre_startup();

	/* Initialization */
	bool check_startup();

	/* De-initialization */
	void shutdown();

	/* Return node description */
	const char *description() const;

	/* Dump node information */
	bool output_info(base_stream &, const std::vector<std::string> &) const;

	/* Join/leave a group */
	void change_group_state(const in6_addr &, bool);

	/* Join/leave an SSM channel */
	void change_source_state(const in6_addr &, const in6_addr &, bool);

	/* Handle incoming ICMPv6 messages. */
	void icmp_message_available(interface *, const in6_addr &, const in6_addr &,
				    icmp6_hdr *, int);

	/* MRD event handler */
	void event(int, void *);

	/* Set new MTU for a destination. */
	void set_mtu(const in6_addr &, uint32_t);

private:

	/* Receive incoming IPv4 packets */
	void data_available(uint32_t);

	/* Handle and translate an incoming IPv4 packet */
	void handle_ipv4(const int, uint8_t *, const uint16_t);

	/* Send an IPv6 packet in fragments. buf must contain an IPv6 packet with a fragment header */
	void send_fragmented_ipv6(const int, uint8_t *, uint16_t, uint16_t);

	/* Return true if a group is an IPv4 ASM group */
	bool is_asm_group(const in6_addr &) const;

	/* Return true if a group is an IPv4 SSM group */
	bool is_ssm_group(const in6_addr &) const;

	/* Return true if a group is an IPv4 ASM group */
	bool is_asm_group(const in_addr) const;

	/* Return true if a group is an IPv4 SSM group */
	bool is_ssm_group(const in_addr) const;

	/* Return true if a group is an IPv4 link-local multicast group */
	bool is_ll_group(const in_addr) const;

	/* Return true if an IPv4 source address is valid for multicast. */
	bool is_valid_source(const in6_addr &) const;

	/* Return true if an IPv4 source address is valid for multicast. */
	bool is_valid_source(const in_addr) const;

	/* Return the embedded IPv4 address (last 32 bits) from an IPv6 address. */
	in_addr get_embedded_address(const in6_addr &) const;

	/* Set the embedded IPv4 address (last 32 bits) of an IPv6 address. */
	void set_embedded_address(in6_addr &, const in_addr) const;

	/* Get MTU for a destination. */
	uint16_t get_mtu(const in_addr) const;

	/* Erase previously set MTU. */
	void erase_mtu(const in6_addr &);

	/* Calculate IPv4 checksum (RFC 1071) */
	uint16_t ipv4_checksum(const uint8_t *, uint16_t) const;

	property_def *m_p_ipv4_interface;
	property_def *m_p_ipv4_address;
	property_def *m_p_unicast_prefix;
	property_def *m_p_asm_prefix;
	property_def *m_p_ssm_prefix;
	int m_igmp_fd;
	bool m_enabled;
	uint32_t m_fragment_id;
	interface *m_interface;
	interface *m_virtual_interface;
	socket0<translator> m_rawsock;
	ip6_hdr m_asm_hdr;
	ip6_hdr m_ssm_hdr;
	us_mfa *m_mfa;

	typedef std::map<in_addr_t, uint16_t> group_mtu_map;
	group_mtu_map m_group_mtu;
};

#endif

/*
 * Multicast Routing Daemon (MRD)
 *   pim/def.h
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

#ifndef _mrd_pim_h_
#define _mrd_pim_h_

#include <mrd/address.h>
#include <mrd/address_set.h>
#include <mrd/support/uint_n.h>

#include <netinet/ip6.h>

class base_stream;

enum pim_msg_type {
	pim_msg_hello = 0,
	pim_msg_register,
	pim_msg_register_stop,
	pim_msg_joinprune,
	pim_msg_bootstrap,
	pim_msg_assert,
	pim_msg_graft,
	pim_msg_graft_ack,
	pim_msg_candidate_rp_adv
};

/*!
 * \brief base PIM message header.
 */
struct pim_message {
	uint8_t vt;
	uint8_t resv1;
	uint16_t checksum;

	pim_msg_type type() const { return (pim_msg_type)(vt & 0xf); }
	const char *type_name() const;

	void construct(pim_msg_type t);

	void build_checksum(const in6_addr &, const in6_addr &, int);
	bool has_valid_checksum(const in6_addr &, const in6_addr &, int len);

} __attribute__ ((packed));

struct pim_hello_option {
	enum {
		holdtime = 1,
		lan_prune_delay = 2,
		dr_priority = 19,
		genid = 20,
		addrlist = 24,
		cisco_old_addrlist = 65001,
	};

	uint16n_t type;
	uint16n_t length;

	void construct(uint16_t type, uint16_t length);

	void add_uint16(uint16_t type, uint16_t value);
	void add_uint16pair(uint16_t type, uint16_t v1, uint16_t v2);
	void add_uint32(uint16_t type, uint32_t value);

	void *data();
	uint16n_t *data16() { return (uint16n_t *)data(); }
	uint32n_t *data32() { return (uint32n_t *)data(); }

	pim_hello_option *next() const;
} __attribute__ ((packed));

/*!
 * \brief PIM Hello message.
 */
struct pim_hello_message : pim_message {
	void construct();

	pim_hello_option *options();
} __attribute__ ((packed));

/*!
 * \brief PIM Register message.
 */
struct pim_register_message : pim_message {
	uint32n_t nb;

	void construct(bool border, bool null);

	ip6_hdr *ip6_header();
	bool border() const;
	bool null() const;
} __attribute__ ((packed));

enum pim_addr_type {
	// we only care about IPv6
	pim_addr_reserved = 0,
	pim_addr_ip6 = 2
};

struct pim_encoded_unicast_address {
	uint8_t family;
	uint8_t type;
	in6_addr addr;

	void construct(const in6_addr &);
} __attribute__ ((packed));

struct pim_encoded_group_address {
	uint8_t family;
	uint8_t type;
	uint8_t zb;
	uint8_t masklen;
	in6_addr addr;

	void construct(const inet6_addr &, bool z, bool b);
	void construct(const inet6_addr &);

	inet6_addr address() const { return inet6_addr(addr, masklen); }

	bool bidir() const;
	bool zoned() const;
} __attribute__ ((packed));

/* from draft-ietf-pim-join-attributes */
struct pim_join_attribute_tlv {
	uint8_t fs_type;
	uint8_t length;

	void construct(bool forward, bool bottom, int type, int length);

	void *data() const;
	bool forward() const;
	bool bottom() const;
};

struct pim_encoded_source_address {
	uint8_t family;
	uint8_t type;
	uint8_t flags;
	uint8_t masklen;
	in6_addr addr;

	void construct(const inet6_addr &, bool wc, bool rpt);

	inet6_addr address() const { return inet6_addr(addr, masklen); }

	bool sparse() const;
	bool wc() const ;
	bool rpt() const;

	int length() const;
	/* advances length() bytes to possibly next encoded source address */
	pim_encoded_source_address *next() const;
} __attribute__ ((packed));

/*!
 * \brief PIM Register Stop message.
 */
struct pim_register_stop_message : pim_message {
	pim_encoded_group_address gaddr;
	pim_encoded_unicast_address uaddr;

	void construct(const inet6_addr &, const inet6_addr &);
} __attribute__ ((packed));

typedef pim_encoded_source_address *pim_jp_g_iterator;

struct pim_joinprune_group {
	pim_encoded_group_address maddr;
	uint16n_t njoins;
	uint16n_t nprunes;

	void construct(const inet6_addr &addr, uint16_t js, uint16_t ps);

	uint16_t length() const;

	pim_jp_g_iterator join_begin() const {
		return pim_jp_g_iterator(addrs());
	}
	pim_jp_g_iterator join_end() const {
		return pim_jp_g_iterator(addrs() + join_count());
	}
	pim_jp_g_iterator prune_begin() const {
		return pim_jp_g_iterator(addrs() + join_count());
	}
	pim_jp_g_iterator prune_end() const {
		return pim_jp_g_iterator(addrs() + join_count() + prune_count());
	}

	address_set &pruned_addrs(address_set &) const;
	bool has_prune_addr(const inet6_addr &) const;

	pim_joinprune_group *next() const;

	pim_encoded_source_address *addrs() const {
		return (pim_encoded_source_address *)(((uint8_t *)this) + sizeof(*this));
	}

private:
	uint16_t join_count() const { return ntoh(njoins); }
	uint16_t prune_count() const { return ntoh(nprunes); }
} __attribute__ ((packed));

/*!
 * \brief PIM Join/Prune message.
 */
struct pim_joinprune_message : pim_message {
	pim_encoded_unicast_address upstream_neigh;
	uint8_t resv1;
	uint8_t ngroups;
	uint16n_t ht;

	void construct(const inet6_addr &, uint8_t groups, uint16_t holdtime);

	/* holdtime in miliseconds */
	uint32_t holdtime() const;
	uint16_t length() const;
	pim_joinprune_group *groups() const;
} __attribute__ ((packed));

struct pim_bootstrap_rp_record {
	pim_encoded_unicast_address addr;
	uint16n_t holdtime;
	uint8_t priority;
	uint8_t resv;
} __attribute__ ((packed));

struct pim_bootstrap_group_def {
	pim_encoded_group_address grpaddr;
	uint8_t rpcount, fragrp;
	uint16_t resv;

	uint16_t length() const;

	pim_bootstrap_rp_record *rps() const;
	pim_bootstrap_group_def *next() const;
} __attribute__ ((packed));

/*!
 * \brief PIM Bootstrap message.
 */
struct pim_bootstrap_message : pim_message {
	uint16n_t fragment;
	uint8_t hash_masklen, bsr_priority;
	pim_encoded_unicast_address bsr_address;

	void construct(uint16_t, uint8_t, uint8_t, const in6_addr &);
	pim_bootstrap_group_def *grps() const;

	bool no_forward() const;
} __attribute__ ((packed));

/*!
 * \brief PIM Candidate RP Adv message.
 */
struct pim_candidate_rp_adv_message : pim_message {
	uint8_t prefixcount;
	uint8_t priority;
	uint16n_t holdtime;
	pim_encoded_unicast_address rp_addr;

	void construct(uint8_t, uint8_t, uint16_t, const in6_addr &);

	pim_encoded_group_address *grps() const;

	uint16_t length() const;
} __attribute__ ((packed));

/*!
 * \brief PIM Assert message.
 */
struct pim_assert_message : pim_message {
	pim_encoded_group_address gaddr;
	pim_encoded_unicast_address saddr;
	uint32n_t metpref;
	uint32n_t metric;

	void construct(const inet6_addr &, const in6_addr &, bool,
		       uint32_t, uint32_t);

	bool rpt() const;
	uint32_t metric_pref() const;
} __attribute__ ((packed));

void _debug_pim_dump(base_stream &, const pim_joinprune_message &);
void _debug_pim_dump(base_stream &, const pim_assert_message &);
void _debug_pim_dump(base_stream &, const pim_bootstrap_message &, int);

#endif


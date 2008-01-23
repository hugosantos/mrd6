/*
 * Multicast Routing Daemon (MRD)
 *   pim_def.cpp
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

#include <mrd/log.h>
#include <mrd/interface.h>
#include <mrdpriv/pim/def.h>

#define _BIT(x)		(1 << (x))
#define _TEST(x, y)	(((x) & _BIT(y)) != 0)

void pim_message::construct(pim_msg_type t) {
	vt = 0x20 | t;
	resv1 = 0;
	checksum = 0;
}

const char *pim_message::type_name() const {
	switch (type()) {
	case pim_msg_hello:
		return "HELLO";
	case pim_msg_register:
		return "REGISTER";
	case pim_msg_register_stop:
		return "REGISTER-STOP";
	case pim_msg_joinprune:
		return "JOIN/PRUNE";
	case pim_msg_bootstrap:
		return "BOOTSTRAP";
	case pim_msg_assert:
		return "ASSERT";
	case pim_msg_candidate_rp_adv:
		return "CANDIDATE-RP-ADV";
	default:
		return "UNKNOWN";
	}
}

void pim_message::build_checksum(const in6_addr &src, const in6_addr &dst, int len) {
	checksum = 0;
	checksum = ipv6_checksum(IPPROTO_PIM, src, dst, this, len);
}

bool pim_message::has_valid_checksum(const in6_addr &src, const in6_addr &dst, int len) {
	uint16_t cksum = checksum;
	checksum = 0;

	uint16_t calc = ipv6_checksum(IPPROTO_PIM, src, dst, this, len);

	checksum = cksum;

	return checksum == calc;
}

void pim_hello_option::construct(uint16_t t, uint16_t l) {
	type = hton(t);
	length = hton(l);
}

void pim_hello_option::add_uint16(uint16_t type, uint16_t value) {
	construct(type, 2);
	data16()[0] = hton(value);
}

void pim_hello_option::add_uint16pair(uint16_t type, uint16_t v1,
				      uint16_t v2) {
	construct(type, 4);
	data16()[0] = hton(v1);
	data16()[1] = hton(v2);
}

void pim_hello_option::add_uint32(uint16_t type, uint32_t value) {
	construct(type, 4);
	data32()[0] = hton(value);
}

pim_hello_option *pim_hello_option::next() const {
	return (pim_hello_option *)(((uint8_t *)this) + sizeof(*this) + ntoh(length));
}

void *pim_hello_option::data() {
	return (((uint8_t *)this) + sizeof(*this));
}

void pim_hello_message::construct() {
	pim_message::construct(pim_msg_hello);
}

pim_hello_option *pim_hello_message::options() {
	return (pim_hello_option *)(((uint8_t *)this) + sizeof(*this));
}

void pim_register_message::construct(bool border, bool null) {
	pim_message::construct(pim_msg_register);

	uint32_t flags = 0;
	if (border)
		flags |= _BIT(31);
	if (null)
		flags |= _BIT(30);
	nb = hton(flags);
}

ip6_hdr *pim_register_message::ip6_header() {
	return (ip6_hdr *)(((uint8_t *)this) + sizeof(*this));
}

bool pim_register_message::border() const {
	return _TEST(ntoh(nb), 31);
}

bool pim_register_message::null() const {
	return _TEST(ntoh(nb), 30);
}

void pim_encoded_unicast_address::construct(const in6_addr &ma) {
	family = pim_addr_ip6;
	type = 0;
	addr = ma;
}

void pim_encoded_group_address::construct(const inet6_addr &ma, bool z, bool b) {
	family = pim_addr_ip6;
	type = 0;

	zb = 0;
	if (z)
		zb |= _BIT(0);
	if (b)
		zb |= _BIT(7);

	masklen = ma.prefixlen;
	addr = ma.address();
}

void pim_encoded_group_address::construct(const inet6_addr &ma) {
	construct(ma, false, false);
}

bool pim_encoded_group_address::bidir() const {
	return _TEST(zb, 0);
}

bool pim_encoded_group_address::zoned() const {
	return _TEST(zb, 7);
}

void pim_join_attribute_tlv::construct(bool f, bool b, int type, int len) {
	fs_type = type;
	if (f)
		fs_type |= _BIT(7);
	if (b)
		fs_type |= _BIT(6);
	length = len;
}

void *pim_join_attribute_tlv::data() const {
	return ((uint8_t *)this) + 2;
}

bool pim_join_attribute_tlv::forward() const {
	return _TEST(fs_type, 7);
}

bool pim_join_attribute_tlv::bottom() const {
	return _TEST(fs_type, 6);
}

void pim_encoded_source_address::construct(const inet6_addr &ma, bool w, bool r) {
	family = pim_addr_ip6;
	type = 0;

	flags = _BIT(2);
	if (w)
		flags |= _BIT(1);
	if (r)
		flags |= _BIT(0);

	masklen = ma.prefixlen;
	addr = ma.address();
}

bool pim_encoded_source_address::sparse() const {
	return _TEST(flags, 2);
}

bool pim_encoded_source_address::wc() const {
	return _TEST(flags, 1);
}

bool pim_encoded_source_address::rpt() const {
	return _TEST(flags, 0);
}

int pim_encoded_source_address::length() const {
	return sizeof(pim_encoded_source_address);
}

pim_encoded_source_address *pim_encoded_source_address::next() const {
	return (pim_encoded_source_address *)(((uint8_t *)this) + length());
}

void pim_register_stop_message::construct(const inet6_addr &ga, const inet6_addr &sa) {
	pim_message::construct(pim_msg_register_stop);

	gaddr.construct(ga);
	uaddr.construct(sa);
}

void pim_joinprune_group::construct(const inet6_addr &addr, uint16_t js, uint16_t ps) {
	maddr.construct(addr);
	njoins = hton(js);
	nprunes = hton(ps);
}

uint16_t pim_joinprune_group::length() const {
	int total = sizeof(*this);
	int count = join_count() + prune_count();

	pim_encoded_source_address *addr = addrs();

	for (int i = 0; i < count; i++, addr = addr->next()) {
		total += addr->length();
	}

	return total;
}

address_set &pim_joinprune_group::pruned_addrs(address_set &as) const {
	pim_encoded_source_address *pa = addrs();

	for (int i = 0; i < join_count(); i++, pa = pa->next());

	for (uint16_t i = 0; i < prune_count(); i++, pa = pa->next()) {
		as += pa->addr;
	}

	return as;
}

bool pim_joinprune_group::has_prune_addr(const inet6_addr &addr) const {
	pim_encoded_source_address *pa = addrs();

	for (int i = 0; i < join_count(); i++, pa = pa->next());

	for (uint16_t i = 0; i < prune_count(); i++, pa = pa->next()) {
		if (pa->addr == addr.address())
			return true;
	}

	return false;
}

pim_joinprune_group *pim_joinprune_group::next() const {
	return (pim_joinprune_group *)(((uint8_t *)this) + length());
}

void pim_joinprune_message::construct(const inet6_addr &neigh, uint8_t groups, uint16_t time) {
	pim_message::construct(pim_msg_joinprune);
	upstream_neigh.construct(neigh);
	resv1 = 0;
	ngroups = groups;
	ht = hton(time);
}

uint32_t pim_joinprune_message::holdtime() const {
	return (uint32_t)ntoh(ht) * 1000;
}

uint16_t pim_joinprune_message::length() const {
	uint16_t len = sizeof(*this);
	pim_joinprune_group *grp = groups();
	for (uint8_t i = 0; i < ngroups; i++, grp = grp->next()) {
		len += grp->length();
	}
	return len;
}

pim_joinprune_group *pim_joinprune_message::groups() const {
	return (pim_joinprune_group *)(((uint8_t *)this) + sizeof(*this));
}

pim_bootstrap_rp_record *pim_bootstrap_group_def::rps() const {
	return (pim_bootstrap_rp_record *)(((uint8_t *)this) + sizeof(*this));
}

uint16_t pim_bootstrap_group_def::length() const {
	return sizeof(*this) + fragrp * sizeof(pim_bootstrap_rp_record);
}

pim_bootstrap_group_def *pim_bootstrap_group_def::next() const {
	return (pim_bootstrap_group_def *)(((uint8_t *)this) + length());
}

void pim_bootstrap_message::construct(uint16_t frag, uint8_t ml, uint8_t prio,
				      const in6_addr &addr) {
	pim_message::construct(pim_msg_bootstrap);

	fragment = hton(frag);
	hash_masklen = ml;
	bsr_priority = prio;
	bsr_address.construct(addr);
}

pim_bootstrap_group_def *pim_bootstrap_message::grps() const {
	return (pim_bootstrap_group_def *)(((uint8_t *)this) + sizeof(*this));
}

bool
pim_bootstrap_message::no_forward() const
{
	return (resv1 & (1 << 7)) != 0;
}

void pim_candidate_rp_adv_message::construct(uint8_t pfxct, uint8_t prio,
					     uint16_t ht, const in6_addr &addr) {
	pim_message::construct(pim_msg_candidate_rp_adv);

	prefixcount = pfxct;
	priority = prio;
	holdtime = hton(ht);

	rp_addr.construct(addr);
}

pim_encoded_group_address *pim_candidate_rp_adv_message::grps() const {
	return (pim_encoded_group_address *)(((uint8_t *)this) + sizeof(*this));
}

uint16_t pim_candidate_rp_adv_message::length() const {
	return sizeof(*this) + prefixcount * sizeof(pim_encoded_group_address);
}

void pim_assert_message::construct(const inet6_addr &grp, const in6_addr &src,
				   bool _rpt, uint32_t pref, uint32_t met) {
	pim_message::construct(pim_msg_assert);

	gaddr.construct(grp);
	saddr.construct(src);

	pref &= ~_BIT(31);
	if (_rpt)
		pref |= _BIT(31);

	metpref = hton(pref);
	metric = hton(met);
}

bool pim_assert_message::rpt() const {
	return _TEST(ntoh(metpref), 31);
}

uint32_t pim_assert_message::metric_pref() const {
	return ntoh(metpref) & ~_BIT(31);
}

static void _do_encoded_address(base_stream &os, const char *type,
				const pim_encoded_source_address &addr) {
	os.xprintf("%s: %{Addr}", type, inet6_addr(addr.addr, addr.masklen));
	if (addr.rpt())
		os.write(" RPT");
	if (addr.wc())
		os.write(" WC");
	os.newl();
}

void _debug_pim_dump(base_stream &os, const pim_joinprune_message &msg) {
	os.xprintf("PIM J/P for %{addr} with holdtime %u\n",
		   msg.upstream_neigh.addr, msg.holdtime());

	int i;
	pim_joinprune_group *grp = msg.groups();

	os.inc_level();

	for (i = 0; i < msg.ngroups; i++, grp = grp->next()) {
		os.writeline(inet6_addr(grp->maddr.addr, grp->maddr.masklen));

		os.inc_level();

		for (pim_jp_g_iterator i = grp->join_begin();
					i != grp->join_end(); ++i)
			_do_encoded_address(os, "Join", *i);

		for (pim_jp_g_iterator i = grp->prune_begin();
					i != grp->prune_end(); ++i)
			_do_encoded_address(os, "Prune", *i);

		os.dec_level();
	}

	os.dec_level();
}

void _debug_pim_dump(base_stream &os, const pim_assert_message &msg) {
	os.xprintf("PIM Assert for (%{addr}, %{addr})%s Pref %u Metric %u\n",
		   msg.saddr.addr, msg.gaddr.addr,
		   msg.rpt() ? " RPT" : "", msg.metric_pref(),
		   ntoh(msg.metric));
}

void _debug_pim_dump(base_stream &os, const pim_bootstrap_message &msg, int len) {
	os.xprintf("PIM Bootstrap from BSR %{addr}, frag %u, masklen %u, prio %u\n",
		   msg.bsr_address.addr, (uint32_t)ntoh(msg.fragment),
		   (uint32_t)msg.hash_masklen, (uint32_t)msg.bsr_priority);

	int off = sizeof(pim_bootstrap_message);
	for (pim_bootstrap_group_def *grp
			= msg.grps(); off < len; grp = grp->next()) {
		if ((off + (int)sizeof(pim_bootstrap_group_def)) > len
			|| (off + grp->length()) > len) {
			os.writeline("Badly formed message.");
			return;
		}

		off += grp->length();
	}

	os.inc_level();

	off = sizeof(pim_bootstrap_message);
	for (pim_bootstrap_group_def *grp
			= msg.grps(); off < len; grp = grp->next()) {
		os.writeline(inet6_addr(grp->grpaddr.addr, grp->grpaddr.masklen));

		os.inc_level();

		pim_bootstrap_rp_record *rp = grp->rps();

		for (int j = 0; j < grp->fragrp; j++) {
			os.xprintf("%{addr}, prio = %i, holdtime = %u\n",
				   rp->addr.addr, (int)rp->priority,
				   (uint32_t)ntoh(rp->holdtime));
			rp++;
		}

		os.dec_level();

		off += grp->length();
	}

	os.dec_level();
}


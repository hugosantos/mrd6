/*
 * Multicast Routing Daemon (MRD)
 *   us_mfa.h
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

#ifndef _mrd_us_mfa_h_
#define _mrd_us_mfa_h_

#include <mrd/mrd.h>
#include <mrd/mfa.h>
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/timers.h>

#ifndef LINUX_NO_TRANSLATOR
#include <mrdpriv/linux/translator.h>
#endif

#include <stdint.h>

#include <list>
#include <map>

class interface;
class router;

struct ip6_hdr;

class us_mfa_group_source;
class us_mfa_group;
class us_mfa;

class us_mfa_group_source : public mfa_group_source {
public:
	us_mfa_group_source(us_mfa_group *, const in6_addr &, uint32_t, action *);

	const in6_addr &address() const { return m_addr; }

	void route(int, ip6_hdr *, uint16_t);

	bool is_iif(int intf) const { return m_iif && m_iif->index() == intf; }
	bool has_oif(interface *) const;

	void change_flags(uint32_t, action);

	void set_iif(interface *);
	void release_iif(interface *);

	void add_oif(interface *);
	void release_oif(interface *);

	void update_stats();

	void output_info(base_stream &, bool, bool) const;

	void clear_interface_references(const inet6_addr &, interface *);

	void get_input_counter(uint64_t &bytes) const;
	void get_forwarding_counter(uint64_t &bytes) const;

private:
	typedef std::vector<interface *> oifs;

	us_mfa_group *m_owner;
	in6_addr m_addr;

	interface *m_iif;
	oifs m_oifs;

	uint32_t m_flags;

	uint32_t m_interest_flags;

	enum {
		stat_forwarded = 0,
		stat_input,
		stat_forwarded_size,
		stat_wrong_iif,
		stat_count
	};

	mutable uint64_t m_stats[stat_count];

	/* enough for 10Gbps+ */
	mutable uint32_t m_fw_bag, m_fw_pkt_bag;

	mutable uint64_t stat_octet_count60s, stat_packet_count60s;
};

class us_mfa_group : public mfa_group {
public:
	us_mfa_group(router *, const inet6_addr &);

	void activate(bool);

	void route(int, ip6_hdr *, uint16_t);

	mfa_group_source *create_source_state(const in6_addr &, void *);
	mfa_group_source *get_source_state(const in6_addr &) const;
	void release_source_state(mfa_group_source *);

	void change_default_flags(uint32_t, mfa_group_source::action);

	void update_stats();

	void output_info(base_stream &, bool, bool) const;

	void clear_interface_references(const inet6_addr &, interface *);

private:
	us_mfa_group_source *match_source(const in6_addr &addr) const;

	typedef std::map<in6_addr, us_mfa_group_source *> sources;

	sources m_sources;

#define _SOURCE_CACHE_LEN	32
	mutable us_mfa_group_source *m_source_cache[_SOURCE_CACHE_LEN];
	bool m_useful_cache;

	void invalidate_source_cache();

	enum state {
		running,
		pending,
		denied
	};

	state m_state;

#ifndef LINUX_NO_TRANSLATOR
	/* Group address */
	const in6_addr &id() const;
	const in6_addr *m_addr;
#endif

	uint32_t m_flags;
	mfa_group_source::action m_actions[mfa_group_source::event_count];

	mutable uint32_t m_fw_bag, m_fw_pkt_bag;
	mutable uint64_t stat_octet_count60s, stat_packet_count60s;
	friend class us_mfa_group_source;
};

#define _SOURCE_CACHE_HASH(x) \
		(((x).s6_addr32[2] ^ (x).s6_addr32[3]) & (_SOURCE_CACHE_LEN-1))

inline us_mfa_group_source *us_mfa_group::match_source(const in6_addr &addr) const {
	if (m_useful_cache) {
		register us_mfa_group_source *possible = m_source_cache[_SOURCE_CACHE_HASH(addr)];
		if (possible && possible->address() == addr)
			return possible;
	}

	sources::const_iterator k = m_sources.find(addr);
	if (k != m_sources.end()) {
		if (m_useful_cache) {
			m_source_cache[_SOURCE_CACHE_HASH(addr)] = k->second;
		}

		return k->second;
	}

	return 0;
}

/*!
 * \brief Implements the User Space Linux Multicast forwarding agent (MFA).
 *
 * This MFA implements does multicast forwarding completly in user-space
 * without any special kernel requirements besides IPv6 support. Internally
 * the forwarding is done using Raw sockets of type PF_PACKET.
 */
class us_mfa : public mfa_core {
public:
	us_mfa();

	bool pre_startup();
	bool check_startup();
	void shutdown();

	bool supports_stats() const { return true; }

	void send_icmpv6_toobig(interface *intf, ip6_hdr *, uint16_t) const;

	void added_interface(interface *);
	void removed_interface(interface *);

	bool output_info(base_stream &, bool counters, bool noempty) const;
	bool output_info(base_stream &, const std::vector<std::string> &) const;

	void discovered_source(int, const inet6_addr &, const inet6_addr &);

	mfa_group *create_group(router *, const inet6_addr &, void *);
	mfa_group *get_group(const inet6_addr &) const;
	void release_group(mfa_group *);

	void route(interface *, ip6_hdr *, uint16_t);

	void change_group_default_flags(uint32_t, mfa_group_source::action);

	void forward(interface *, ip6_hdr *, uint16_t) const;

	uint32_t m_grpflags;
	mfa_group_source::action m_grpactions[mfa_group_source::event_count];

	void clear_interface_references(interface *);

private:
	void data_available(uint32_t);
	void handle_ipv6(int, uint8_t *, uint16_t);

	void log_failed_packet(const interface *, int) const;

	socket0<us_mfa> m_rawsock;

	data_plane_source_discovery m_sourcedisc;

#ifndef LINUX_NO_TRANSLATOR
	translator m_translator;
	friend class translator;
	friend class us_mfa_group_source;
#endif

#ifndef LINUX_NO_MMAP
	void *m_mmaped;
	uint32_t m_mmapedlen;
	uint32_t m_framesize;
	uint8_t *m_mmapbuf;
#endif

	void update_stats();

	timer<us_mfa> m_stat_timer;

	us_mfa_group *match_group(const in6_addr &) const;

	typedef std::map<inet6_addr, us_mfa_group *> groups;

	groups m_groups;

	typedef std::map<in6_addr, us_mfa_group *> singles;
	mutable singles m_singles;

#define _GROUP_CACHE_LEN 128
	struct grp_cache_entry {
		in6_addr addr;
		us_mfa_group *entry;
	};
	mutable grp_cache_entry m_grp_cache[_GROUP_CACHE_LEN];

	void invalidate_group_cache();
	void invalidate_group_cache(const in6_addr &);
};

#define _GROUP_CACHE_HASH(x) \
		(((x).s6_addr32[2] ^ (x).s6_addr32[3]) & (_GROUP_CACHE_LEN-1))

inline us_mfa_group *us_mfa::match_group(const in6_addr &addr) const {
	grp_cache_entry &ent = m_grp_cache[_GROUP_CACHE_HASH(addr)];
	if (ent.addr == addr && ent.entry) {
		return ent.entry;
	}

	singles::const_iterator i = m_singles.find(addr);
	if (i != m_singles.end()) {
		ent.addr = addr;
		ent.entry = i->second;
		return i->second;
	}

	for (groups::const_iterator k = m_groups.begin();
				k != m_groups.end(); ++k) {
		if (k->first.matches(addr)) {
			m_singles[addr] = k->second;
			return k->second;
		}
	}

	return 0;
}

inline bool us_mfa_group_source::has_oif(interface *oif) const {
	return std::find(m_oifs.begin(), m_oifs.end(), oif) != m_oifs.end();
}

#endif


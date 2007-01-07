/*
 * Multicast Routing Daemon (MRD)
 *   bsd/mfa.h
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

#ifndef _mrd_bsd_mfa_h_
#define _mrd_bsd_mfa_h_

#include <list>
#include <map>
#include <stdint.h>
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/log.h>
#include <mrd/mfa.h>
#include <mrd/mrd.h>
#include <mrd/timers.h>
#include <sys/param.h>
#include <netinet6/ip6_mroute.h>

class interface;
class router;

struct ip6_hdr;

class bsd_mfa_group_source;
class bsd_mfa_group;
class bsd_mfa;

class bsd_mfa_group_source : public mfa_group_source {
public:
	bsd_mfa_group_source(bsd_mfa_group *, const in6_addr &, uint32_t, action *);
	virtual ~bsd_mfa_group_source();

	const in6_addr &address() const { return m_addr.address(); }

	bool is_iif(interface *intf) const { return intf == m_iif; }
	bool has_oif(interface *) const;

	void change_flags(uint32_t, action);

	void set_iif(interface *);
	void release_iif(interface *);

	void add_oif(interface *);
	void release_oif(interface *);

	void get_input_counter(uint64_t &) const;
	void get_forwarding_counter(uint64_t &) const;

	void output_info(base_stream &) const;

private:
	typedef std::vector<interface *> oifs;

	bsd_mfa_group *m_owner;
	inet6_addr m_addr;

	interface *m_iif;
	oifs m_oifs;

	mf6cctl m_bsd_state;

	uint32_t m_flags;
	uint32_t m_interest_flags;

	friend class bsd_mfa;
};

class bsd_mfa_group : public mfa_group {
public:
	bsd_mfa_group(router *, const inet6_addr &);

	const inet6_addr &addr() const { return m_addr; }

	void activate(bool);

	mfa_group_source *create_source_state(const in6_addr &, void *);
	mfa_group_source *get_source_state(const in6_addr &) const;
	void release_source_state(mfa_group_source *);

	void change_default_flags(uint32_t, mfa_group_source::action);

	void output_info(base_stream &) const;

private:
	bsd_mfa_group_source *match_source(const in6_addr &addr) const;

	typedef std::map<in6_addr, bsd_mfa_group_source *> sources;

	sources m_sources;

	enum state {
		running,
		pending,
		denied
	};

	state m_state;

	inet6_addr m_addr;

	uint32_t m_flags;
	mfa_group_source::action m_actions[mfa_group_source::event_count];
};

inline bsd_mfa_group_source *bsd_mfa_group::match_source(const in6_addr &addr) const {
	sources::const_iterator k = m_sources.find(addr);
	if (k != m_sources.end()) {
		return k->second;
	}

	return 0;
}

class bsd_mfa : public mfa_core {
public:
	bsd_mfa();

	bool pre_startup();
	bool check_startup();
	void shutdown();

	bool supports_stats() const { return true; }

	void added_interface(interface *);
	void removed_interface(interface *);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

	void data_available(interface *, int);

	int vif(interface *iif) const;
	void commit(mf6cctl *, bool = false);

	void discovered_source(int, const inet6_addr &, const inet6_addr &);

	mfa_group *create_group(router *, const inet6_addr &, void *);
	mfa_group *get_group(const inet6_addr &) const;
	void release_group(mfa_group *);

	void change_group_default_flags(uint32_t, mfa_group_source::action);

	void forward(interface *, ip6_hdr *, uint16_t) const;

	uint32_t m_grpflags;
	mfa_group_source::action m_grpactions[mfa_group_source::event_count];

	void get_input_counter(const bsd_mfa_group_source *, uint64_t &);
	void get_forwarding_counter(const bsd_mfa_group_source *, uint64_t &);

	void get_source_counters(const bsd_mfa_group_source *, sioc_sg_req6 *);

private:
	int m_icmpsock;

	void kernel_data_pending(uint32_t);

	socket0<bsd_mfa> m_sock;

	std::map<interface *, int> vifs;
	std::map<int, interface *> rev_vifs;

	data_plane_source_discovery data_plane_sourcedisc;

	bsd_mfa_group *match_group(const in6_addr &) const;

	typedef std::map<inet6_addr, bsd_mfa_group *> groups;

	groups m_groups;
};

inline bsd_mfa_group *bsd_mfa::match_group(const in6_addr &addr) const {
	for (groups::const_iterator k = m_groups.begin();
				k != m_groups.end(); ++k) {
		if (k->first.matches(addr)) {
			return k->second;
		}
	}

	return 0;
}

inline bool bsd_mfa_group_source::has_oif(interface *oif) const {
	return std::find(m_oifs.begin(), m_oifs.end(), oif) != m_oifs.end();
}

#endif


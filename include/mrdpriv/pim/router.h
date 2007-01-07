/*
 * Multicast Routing Daemon (MRD)
 *   pim/router.h
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

#ifndef _mrd_pim_router_h_
#define _mrd_pim_router_h_

#include <mrd/mrd.h>
#include <mrd/router.h>
#include <mrd/group.h>
#include <mrd/node.h>

#include <mrd/support/ptree.h>

#include <mrdpriv/pim/interface.h>

#include <sys/socket.h>

#include <list>

struct pim_message;
struct pim_bootstrap_message;
struct pim_candidate_rp_adv_message;

class pim_interface;
class pim_group_node;
class pim_interface;
class pim_neighbour;
class pim_router;

struct pim_source_filter {
	/* for Reject, value is true */
	bool filter_mode;
	std::set<inet6_addr> sources;

	bool accepts(const in6_addr &) const;
};

class pim_intfconf_node : public intfconf_node {
public:
	typedef intfconf_node base;

	pim_intfconf_node(intfconf *);

	bool check_startup();

	bool fill_defaults();

	bool set_property(const char *, const char *);
	bool call_method(int, base_stream &, const std::vector<std::string> &);

	uint32_t hello_interval() const;
	uint32_t holdtime() const;
	uint32_t joinprune_interval() const;
	uint32_t joinprune_holdtime() const;
	uint32_t joinprune_supression_timeout() const;
	uint32_t data_timeout() const;
	uint32_t register_supression_timeout() const;
	uint32_t probe_time() const;
	uint32_t assert_timeout() const;
	uint32_t random_delay_join_timeout() const;
	uint32_t dr_priority() const;
	uint32_t register_stop_rate_limit() const;
	uint32_t register_stop_rate_timelen() const;
	uint32_t propagation_delay() const;
	uint32_t override_interval() const;

	bool support_old_cisco_addrlist() const;

	pim_source_filter neigh_acl;

	bool neigh_acl_accepts(const in6_addr &) const;
};

enum rp_source {
	rps_static,
	rps_embedded,
	rps_rp_set,
	rps_join
};

enum rp_access {
	rpa_any,
	rpa_allow,
	rpa_deny
};

enum spt_option {
	dont_use = 0,
	always_use
};

class pim_groupconf_node : public groupconf_node {
public:
	typedef groupconf_node base;

	pim_groupconf_node(groupconf *);

	bool check_startup();

	bool fill_defaults();

	bool set_property(const char *, const char *);
	bool call_method(int, base_stream &, const std::vector<std::string> &);
	bool increment_property(const char *, const char *);

	bool rp_for_group(const in6_addr &grpaddr, in6_addr &rpaddr,
			  rp_source &) const;

	/* RP rejection policy */
	enum {
		RPRejRegisterStop,
		RPRejSilentIgnore,
		RPRejLogIgnore
	};

	int rp_rejected_source_policy() const;

	pim_source_filter rp_source_acl;

	bool rp_source_acl_accepts(const pim_group_node *, const in6_addr &) const;
};

class pim_rp_set : public node {
public:
	pim_rp_set(pim_router *);

	bool check_startup();

	const char *description() const;

	bool add_entry(const inet6_addr &, const inet6_addr &, uint8_t, uint16_t, bool);
	bool remove_entry(const inet6_addr &, const inet6_addr &);
	void update_entries(const inet6_addr &rpaddr, uint8_t prio,
			uint16_t holdtime, const std::list<inet6_addr> &grps);

	void store_from_message(const in6_addr &, pim_bootstrap_message *msg, uint16_t len);
	void build_message(pim_bootstrap_message *msg, uint16_t &len) const;

	void clear();

	int count_entries() const;

	void set_hashmask(uint16_t);
	uint16_t get_hashmask() const { return m_hashmask; }

	inet6_addr rp_for(const inet6_addr &) const;

	bool call_method(int id, base_stream &, const std::vector<std::string> &);

	bool output_info(base_stream &ctx, const std::vector<std::string> &) const;

private:
	struct entry;

	struct group_set : ptree_node {
		inet6_addr prefix;
		std::list<entry *> entries;

		uint8_t greater_prio() const;

		bool has_entry(entry *) const;
		bool release_entry(const inet6_addr &grpaddr,
			const inet6_addr &, bool verbose = true);

		std::list<entry *>::iterator find_entry(entry *);
		std::list<entry *>::iterator find(const in6_addr &);

		void insert_entry(entry *);

		bool add_entry(pim_rp_set *, const in6_addr &, uint8_t, uint16_t, bool);
	};

	struct entry {
		entry(pim_rp_set *);

		void update_holdtime(uint16_t, bool andtimer = true);

		group_set *owner;
		uint8_t prio;
		uint16_t holdtime;
		in6_addr rpaddr;
		timer1<pim_rp_set, entry *> timer;
	};

	void handle_entry_timeout(entry * &);

	typedef ptree<inet6_addr, group_set> db;

	db m_db;
	uint16_t m_hashmask;
};

class pim_bsr {
public:
	pim_bsr(pim_router *);

	/* 'Public' interface used by pim_router */

	bool check_startup();

	void handle_bootstrap_message(pim_interface *intf, const sockaddr_in6 *,
			const sockaddr_in6 *, pim_bootstrap_message *, uint16_t);
	void handle_candidate_rp_adv(pim_interface *intf, const sockaddr_in6 *,
			pim_candidate_rp_adv_message *, uint16_t);

	in6_addr rp_from_rpset(const inet6_addr &groupid) const;

	void output_info(base_stream &) const;

	void acquired_primary_address();
	void leaving();
	void shutdown();

	void found_new_neighbour(pim_neighbour *);

	/* Internal stuff */

	bool is_bsr() const { return m_bsr_state == BSRElected; }

	void send_bootstrap_message(sockaddr_in6 *) const;
	void broadcast_rp_set_changed(pim_rp_set *) const;

	void enable_rp_adv(const inet6_addr &, bool);

	uint16_t get_default_hashmask() const { return m_p_hashmask->get_integer(); }

	enum candidate_bsr_state {
		BSRCandidate,
		BSRPending,
		BSRElected
	};

	enum no_cand_bsr_state {
		NCNoInfo,
		NCAcceptAny,
		NCAcceptPreferred
	};

	base_stream &log() const;

private:
	property_def *m_p_enable_bootstrap;
	property_def *m_p_bsr_candidate;
	property_def *m_p_bsr_priority;
	property_def *m_p_bsr_timeout;
	property_def *m_p_bsr_period;
	property_def *m_p_sz_timeout;
	property_def *m_p_rp_candidate;
	property_def *m_p_rp_cand_prio;
	property_def *m_p_rp_cand_adv_period;
	property_def *m_p_rp_cand_holdtime;

	property_def *m_p_hashmask;

	void send_leave_bootstrap() const;
	void send_leave_rp_candidate() const;

	candidate_bsr_state m_bsr_state;
	timer<pim_bsr> m_bsr_timer, m_sz_timer;
	int m_bsr_preferred_priority;
	inet6_addr m_bsr_preferred;

	no_cand_bsr_state m_nc_bsr_state;

	void handle_bsr_timeout();
	void handle_sz_timeout();

	bool is_bsr_preferred(const pim_bootstrap_message *) const;
	bool is_bsr_preferred(const in6_addr &, int prio) const;

	void to_pending_bsr();
	void reset_preferred_bsr();
	void im_the_elected_bsr(bool);
	uint32_t bsr_rand_override() const;
	void accept_preferred_bsr(const in6_addr *, int prio, pim_bootstrap_message *, uint16_t);
	void refresh_sz_timer();
	void sz_expired();
	void has_new_bsr(bool);
	void switch_bsr_state(candidate_bsr_state);
	void change_nc_state(no_cand_bsr_state);

	timer<pim_bsr> m_rp_adv_timer;

	void handle_rp_adv_timer();

	mutable time_t m_last_sent_bsm;
	uint32_t m_rp_adv_count;
	pim_rp_set m_rp_set;
};

/*!
 * \brief core PIM protocol implementation.
 *
 * `pim_router' implements all the PIM state management logic:
 * from group/source creation, to pim interface handling.
 */
class pim_router : public router {
public:
	pim_router();
	~pim_router();

	const char *name() const { return "pim"; }

	const char *description() const;

	bool check_startup();
	bool router_startup();
	void shutdown();

	void created_group(group *);
	void released_group(group *);
	void release_group(pim_group_node *);

	void add_interface(interface *);
	void remove_interface(interface *);

	intfconf_node *create_interface_configuration(intfconf *);
	groupconf_node *create_group_configuration(groupconf *);

	bool output_info(base_stream &ctx, const std::vector<std::string> &) const;

	pim_interface *get_interface(interface *) const;
	pim_interface *get_interface(int) const;

	virtual pim_group_node *create_group(const inet6_addr &, node *);
	pim_group_node *get_group(const inet6_addr &) const;

	void found_new_neighbour(pim_neighbour *) const;
	void lost_neighbour(pim_neighbour *) const;
	pim_neighbour *get_neighbour(const inet6_addr &) const;

	pim_neighbour *get_rpf_neighbour(const in6_addr &) const;

	std::list<in6_addr> all_global_addrs() const;

	bool sendmsg(const sockaddr_in6 *from, sockaddr_in6 *dst, pim_message *, uint16_t) const;
	bool send_all(pim_message *, uint16_t len, const sockaddr_in6 * = 0) const;
	bool send_all_neighbours(pim_message *, uint16_t len, const sockaddr_in6 * = 0) const;

	bool send_register(const in6_addr &src, const in6_addr &dst,
			   pim_register_message *msg, int payload) const;
	bool send_register_probe(const in6_addr &src, const in6_addr &dst,
				 pim_register_message *msg, int payload) const;

	void send_register_stop_to_router(const inet6_addr &,
					  const in6_addr &,
					  const in6_addr &src,
					  const in6_addr &from) const;

	const inet6_addr &my_address() const { return m_my_address; }
	void check_my_address(bool force = false);

	void interface_state_changed(pim_interface *, pim_interface::state oldstate);

	void dr_changed(pim_interface *, bool);

	bool mfa_create_state_if_needed() const { return true; }
	void mfa_notify(mfa_group_source *, const in6_addr &, const in6_addr &,
			uint32_t, mfa_group_source::action, interface *,
			ip6_hdr *, uint16_t, uint16_t);

#ifndef PIM_NO_BSR
	pim_bsr &bsr() { return m_bsr; }
#endif

	bool call_method(int id, base_stream &, const std::vector<std::string> &);

	base_stream &log_router_desc(base_stream &) const;

	mutable socket6<pim_router> pim_sock;

private:
	void data_available(uint32_t);

	void event(int, void *);

	void handle_garbage_collector();

	void discovered_source(interface *, const inet6_addr &,
			       const inet6_addr &, source_discovery_origin *);

	bool send_register_generic(const in6_addr &src, const in6_addr &dst,
				   pim_register_message *msg, int payload, int) const;

	timer<pim_router> m_gc;

	inet6_addr m_my_address;

#ifndef PIM_NO_BSR
	pim_bsr m_bsr;

	friend class pim_bsr;
#endif
};

extern pim_router *pim;

#endif


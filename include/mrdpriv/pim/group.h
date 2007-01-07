/*
 * Multicast Routing Daemon (MRD)
 *   pim/group.h
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

#ifndef _mrd_pim_group_h_
#define _mrd_pim_group_h_

#include <mrd/mrd.h>
#include <mrd/group.h>
#include <mrd/rib.h>

#include <mrdpriv/pim/neighbour.h>
#include <mrdpriv/pim/router.h>

#include <mrd/support/refcount.h>

#include <map>

struct pim_message;
struct pim_joinprune_group;
struct pim_joinprune_message;

class pim_groupconf_node;

class pim_interface;
class pim_group_node;
class pim_source_state_base;

class mfa_group;
class mfa_group_source;

class source_discovery_origin;

/*!
 * \brief Represents PIM output interface. Used in PIM source states.
 */
class pim_oif {
public:
	pim_oif(pim_source_state_base *owner, interface *intf);
	virtual ~pim_oif();

	interface *intf() const { return m_intf; }
	pim_interface *pim_intf() const;

	enum interest {
		NoInfo,
		Include,
		Exclude
	};

	void change_local_membership(interest);

	void update(bool join, uint32_t hold = 0);

	interest get_interest() const;
	interest get_interest(bool includelocal) const;

	virtual interest get_local_interest() const;
	interest get_real_local_interest() const { return m_local; }

	virtual bool has_interest() const;

	void dr_changed(bool);

	void output_info(base_stream &) const;

	enum state {
		JPNoInfo,
		Joined,
		PendingPrune,
		Pruned
	};

	base_stream &log() const;

protected:
	void release();
	void timed_out();
	virtual void pp_timed_out() = 0;

	virtual void inner_update(bool join, uint32_t hold) = 0;

	virtual interest get_internal_interest(interest local) const;

	bool needs_supressing() const;
	uint32_t jp_override_interval() const;

	bool change_state(state);
	virtual void changed_state(interest);

	virtual void output_extra_info(base_stream &) const;

	pim_source_state_base *m_state;
	interface *m_intf;
	timer<pim_oif> m_timer, m_pp_timer;
	interest m_local;

	state m_jpstate;
};

class pim_common_oif : public pim_oif {
public:
	pim_common_oif(pim_source_state_base *owner, interface *intf);

	bool has_interest() const;

	enum assert_state {
		AssertNoInfo,
		LostAssert,
		WonAssert
	};

	assert_state current_assert_state() const;
	pim_neighbour *assert_winner() const;

	void change_assert_state(assert_state, bool propagate = true);
	void store_assert_info(pim_neighbour *, uint32_t, uint32_t);
	void restart_assert_timer();
	void restart_assert_timer_minus_override();
	void delete_assert_info();

protected:
	void pp_timed_out();
	void assert_timed_out();
	void inner_update(bool join, uint32_t hold);

	interest get_internal_interest(interest local) const;

	void output_extra_info(base_stream &) const;

	assert_state m_assert_state;
	timer<pim_common_oif> m_assert_timer;
	pim_neighbour *m_assert_winner;
	uint32_t m_assert_winner_pref, m_assert_winner_metric;
};

class pim_sg_rpt_oif : public pim_oif {
public:
	pim_sg_rpt_oif(pim_source_state_base *owner, interface *intf);

private:
	void pp_timed_out();
	void inner_update(bool join, uint32_t hold);
};

class pim_source_state_base : public refcountable {
public:
	pim_source_state_base(pim_group_node *owner, const inet6_addr &);
	virtual ~pim_source_state_base();

	virtual bool check_startup();
	virtual bool output_info(base_stream &) const = 0;

	pim_group_node *owner() const;
	const in6_addr &addr() const;

	virtual interface *iif() const = 0;

	pim_neighbour::upstream_path *upstream_path() const;

	bool set_oif(interface *, uint32_t holdtime, bool join = true);
	bool set_local_oif(interface *, bool join = true);

	virtual bool remove_oif(interface *);
	virtual bool release_oif(interface *, bool local);
	virtual pim_oif *get_oif(interface *) const;

	int count_oifs() const;

	virtual bool is_source_local() const { return false; }

	/* pim machinary */

	virtual bool is_wildcard() const = 0;
	virtual bool is_rpt() const = 0;

	/* returns the PIM neighbour which is acting as upstream
	 * for this source state */
	virtual pim_neighbour *upstream_neighbour() const = 0;
	/* returns true if we are the upstream neighbour for this state,
	 * i.e. this source is local */
	virtual bool am_self_upstream() const = 0;

	virtual uint32_t path_metric() const = 0;
	virtual uint32_t path_protocol() const = 0;

	/* by default returns true if get_downstream_interest != NoInfo */
	virtual bool join_desired() const;
	/* returns the downstream Oif interest */
	virtual pim_oif::interest get_downstream_interest() const;

	pim_oif::interest get_oif_downstream_interest(bool) const;

	/* by default the join_target() is S from (S,G) */
	virtual const in6_addr &join_target() const;

	/* internal machinery */

	/* checks if the state wishes to remain alive, and if not,
	 * removes itself */
	bool check_interest();

	bool check_interest_and_update_upstream();

	/* by default state_desired() has the same value as join_desired() */
	virtual bool state_desired() const;

	virtual void check_upstream_path();

	/* called when the upstream neighbour changes and the
	 * upstream path must be constructed */
	virtual void build_upstream_state();

	/* called to update the upstream path when state interest changes */
	void update_upstream();

	/* events */

	/* called when the RP for G changes */
	virtual void rp_changed() = 0;
	/* called when the DR for interface I changes */
	virtual void dr_changed(pim_interface *, bool islocal);
	/* called when the (*,G) state is created or destroyed */
	virtual void wildcard_state_existance_changed(bool created);
	/* called when one of the Oifs changes state */
	virtual void oif_changed_state(pim_oif *, pim_oif::interest previous_int) = 0;

	/* called when an interface is being removed and any references
	 * to it must be removed */
	virtual void clear_interface_references(interface *);

	/* definitions */

	typedef std::list<pim_oif *> oifs;

	/* helpers, utils */
	int32_t uptime() const { return tval::now() - m_creation_time; }

	/* logging */
	base_stream &log() const;

	virtual void output_name(base_stream &) const = 0;

protected:
	pim_oif *create_oif(interface *);
	virtual pim_oif *create_oif(pim_source_state_base *, interface *) const = 0;

	void output_common_info(base_stream &ctx) const;

	/* internal semi-events */
	virtual void removing_oif(pim_oif *);
	virtual void upstream_changed();

	void destructor();

	pim_group_node *m_owner;
	in6_addr m_addr;

	tval m_creation_time;

	oifs m_oifs;

	pim_neighbour::upstream_path *m_upstream_path;

	bool m_previous_interest;
};

inline pim_group_node *pim_source_state_base::owner() const {
	return m_owner;
}

inline const in6_addr &pim_source_state_base::addr() const {
	return m_addr;
}

inline pim_neighbour::upstream_path *pim_source_state_base::upstream_path() const {
	return m_upstream_path;
}

class pim_source_state_common : public pim_source_state_base, public mrib_watcher_target {
public:
	pim_source_state_common(pim_group_node *grp, const inet6_addr &);

	bool check_startup();

	interface *iif() const;

	uint32_t path_metric() const;
	uint32_t path_protocol() const;

	pim_neighbour *upstream_neighbour() const;
	bool am_self_upstream() const;

	virtual const in6_addr &join_destination() const = 0;

	/* mrib_watcher required methods */
	const in6_addr &target_destination() const;
	const inet6_addr &target_group() const;

	void check_upstream_path();

	/* pim assert machinery */

	/* implements PIM's CouldAssert macro */
	virtual bool could_assert(interface *) const;
	/* implements PIM's AssertTrackingDesired macro */
	virtual bool assert_tracking_desired(interface *) const;

	bool check_assert(interface *, const inet6_addr &, bool rpt,
				uint32_t metric, uint32_t pref) const;
	/* sends a PIM Assert message for this source state in interface I */
	void send_assert(pim_interface *);
	void send_assert_cancel(pim_interface *);

	/* events */
	void found_new_neighbour(pim_neighbour *);
	void neighbour_lost(pim_neighbour *);

	void clear_interface_references(interface *);

protected:
	virtual void neighbour_changed(pim_neighbour_watcher_base *);
	pim_oif *create_oif(pim_source_state_base *, interface *) const;

	void assert_wstate_actions1(pim_common_oif *);
	void assert_lstate_actions2(pim_common_oif *, pim_neighbour *, uint32_t, uint32_t);

	/* internal semi-events */
	virtual void changed_iif(interface *);
	virtual void removing_iif(interface *);

	interface *m_iif;

	pim_neighbour_watcher<pim_source_state_common> m_neigh_watcher;
};

/*!
 * \brief Represents a PIM source state (*, G) or (S, G).
 */
class pim_group_source_state : public pim_source_state_common {
public:
	pim_group_source_state(pim_group_node *grp, const inet6_addr &addr);
	virtual ~pim_group_source_state();

	bool check_startup();
	bool output_info(base_stream &) const;

	bool spt() const { return m_spt; }
	bool is_rpt() const { return false; }
	bool is_wildcard() const { return false; }

	/* join_destination for a (S,G) state is S */
	const in6_addr &join_destination() const;

	void set_spt(bool);

	bool is_source_local() const { return m_local; }
	bool has_downstream_interest(bool includelocal) const;

	void forward_to_rp(interface *, ip6_hdr *, uint16_t);
	void register_stop();

	void trigger_register_stop(const in6_addr *);
	void send_register_stop_to_router(const in6_addr *) const;

	void forward(interface *, ip6_hdr *, uint16_t);

	void trigger_assert(interface *);

	/* implements lost_assert(S,G,rpt,I) */
	bool lost_assert_rpt(pim_common_oif *) const;

	void inherited_oif_changed_state(pim_oif *, pim_oif::interest);

	void restart_kat();

	pim_oif::interest get_downstream_interest() const;

	void rp_changed();

	/* implements PIM (S,G) CouldAssert macro */
	bool could_assert(interface *) const;
	/* implements PIM's (S,G) AssertTrackingDesired macro */
	bool assert_tracking_desired(interface *) const;

	void handle_assert(interface *, const in6_addr &, bool rpt, uint32_t, uint32_t);

	pim_oif::interest get_inherited_oif_downstream_interest() const;

protected:
	bool inherited_includes(pim_oif *) const;

	void update_rpts() const;

	void build_single_jp_msg(pim_joinprune_message *) const;
	void send_probe();

	void output_name(base_stream &) const;

	void wildcard_state_existance_changed(bool created);
	void oif_changed_state(pim_oif *, pim_oif::interest);
	void merge_inherited_oifs();

	virtual bool join_desired() const;
	virtual bool state_desired() const;

	void changed_iif(interface *);
	void removing_iif(interface *);
	void removing_oif(pim_oif *);
	void upstream_changed();

	void update_fw_counters();

	void update_fib(interface *, int change);
	void check_downstream_activity();

	bool m_spt, m_local;
	mfa_group_source *m_mfa_inst;

	bool m_downstream_activity;

	const oifs *m_inherited_oifs;

	bool m_kat_enabled;
	tval m_kat_last_update;
	timer<pim_group_source_state> m_register_supression_timer;
	bool m_sent_probe;

	uint64_t m_fw_counter;

	struct register_stop_state {
		uint32_t count;
		uint64_t last;
	};

	std::map<in6_addr, register_stop_state> m_register_stop_router_rates;

	enum assert_state {
		noinfo,
		won_assert,
		lost_assert
	};

	assert_state m_assert_state;

	friend class pim_group_node;
};

inline void pim_group_source_state::restart_kat() {
	m_kat_enabled = true;
	m_kat_last_update.update_to_now();
}

class pim_group_source_rpt_state : public pim_source_state_base {
public:
	pim_group_source_rpt_state(pim_group_node *, const inet6_addr &);

	interface *iif() const;

	uint32_t path_metric() const;
	uint32_t path_protocol() const;

	pim_neighbour *upstream_neighbour() const;
	bool am_self_upstream() const;

	pim_oif::interest get_downstream_interest() const;

	void set_local_interest(pim_oif::interest);

	bool join_desired() const;
	bool state_desired() const;
	void rp_changed();

	bool output_info(base_stream &) const;
private:
	bool is_rpt() const { return true; }
	bool is_wildcard() const { return false; }

	void oif_changed_state(pim_oif *, pim_oif::interest);

	void wildcard_state_existance_changed(bool created);

	pim_oif *create_oif(pim_source_state_base *, interface *) const;

	void output_name(base_stream &) const;

	pim_oif::interest m_local_interest;

	friend class pim_group_node;
};

class pim_group_wildcard_state : public pim_source_state_common {
public:
	pim_group_wildcard_state(pim_group_node *);
	~pim_group_wildcard_state();

	void build_upstream_state();

	void rp_changed();

	const in6_addr &join_target() const;
	const in6_addr &join_destination() const;

	const oifs *get_oifs() const { return &m_oifs; }

	/* implements PIM (*,G) CouldAssert macro */
	bool could_assert(interface *) const;
	void handle_assert(interface *, const in6_addr &, bool rpt, uint32_t, uint32_t);

	bool output_info(base_stream &) const;

	bool state_desired() const;

private:
	bool is_rpt() const { return true; }
	bool is_wildcard() const { return true; }

	void removing_oif(pim_oif *);
	void upstream_changed();

	void oif_changed_state(pim_oif *, pim_oif::interest);

	void output_name(base_stream &) const;
};

class pim_group_node : public group_node {
public:
	pim_group_node(router *, const inet6_addr &, pim_groupconf_node *);
	virtual ~pim_group_node();

	const char *description() const { return "PIM active multicast group information"; }

	static bool calculate_embedded_rp_addr(const in6_addr &, inet6_addr &);

	void shutdown();

	bool output_info(base_stream &, const std::vector<std::string> &) const;

	void garbage_collect();

	const inet6_addr &id() const { return m_addr; }

	void set_rp();
	void set_rp(const inet6_addr &, rp_source);

	inet6_addr rp_for_group(rp_source &) const;

	bool is_embedded() const { return !m_embedded_rpaddr.is_any(); }
	const inet6_addr &embedded_rp_addr() const { return m_embedded_rpaddr; }

	void rp_set_changed();

	void attached(group *);

	bool attach(group *, const pim_groupconf_node *);

	void dettached();

	bool check_startup();

	bool has_interest_in_group() const;
	bool has_downstream_interest(const in6_addr &) const;

	pim_source_state_base *create_state(const inet6_addr &, bool rpt);
	pim_source_state_base *create_state(const inet6_addr &, bool rpt,
					interface *oif, bool, uint32_t = 0);

	pim_source_state_base *get_state(const inet6_addr &, bool rpt) const;
	pim_group_source_state *get_state(const inet6_addr &addr) const
		{ return (pim_group_source_state *)get_state(addr, false); }
	pim_group_source_rpt_state *get_rpt_state(const inet6_addr &addr) const
		{ return (pim_group_source_rpt_state *)get_state(addr, true); }

	address_set source_state_set() const;
	address_set local_source_state_set() const;

	void remove_state(pim_source_state_base *);

	bool create_wildcard();
	bool create_wildcard(interface *oif, bool, uint32_t);
	bool has_wildcard() const;

	pim_group_wildcard_state *wildcard() const;

	bool has_rp_path() const { return m_rp_path.valid; }
	interface *interface_towards_rp() const { return g_mrd->get_interface_by_index(m_rp_path.dev); }
	const in6_addr &pref_source_towards_rp() const { return m_rp_path.prefsrc; }

	const in6_addr &rpaddr() const { return m_rpaddr; }
	bool has_rp() const { return !IN6_IS_ADDR_UNSPECIFIED(&m_rpaddr); }

	void do_register(const in6_addr *, ip6_hdr *, uint16_t, bool);
	void register_stop(const inet6_addr &, const inet6_addr &);

	void clear_interface_references(interface *);

	void subscriptions_changed(const group_interface *, group_interface::event_type, const address_set &);

	void found_new_neighbour(pim_neighbour *) const;
	void lost_neighbour(pim_neighbour *) const;

	void dr_changed(pim_interface *, bool);

	void rpt_upstream_changed();
	void rpt_update_upstream();
	void inherited_oif_changed_state(pim_oif *, pim_oif::interest);

	bool is_ssm() const { return m_ssm; }
	bool is_self_rp() const { return m_selfrp; }

	void forward_to_rp(pim_group_source_state *, interface *, ip6_hdr *, uint16_t);
	void failed_to_forward_to_rp(const char *);

	void send_register_stop_to_router(const in6_addr &src,
					  const in6_addr &from) const;

	pim_groupconf_node *get_conf() const { return m_conf; }

	mfa_group *mfa() const { return m_mfa_inst; }

	virtual void discovered_source(interface *, const inet6_addr &,
				       source_discovery_origin *);

	bool has_interest_on(const in6_addr &) const;

private:
	bool handle_kat_expired(pim_group_source_state *);
	void rp_path_changed(uint32_t);

	virtual bool rp_acl_accept(const in6_addr &) const;
	virtual bool rp_acl_accept_source(const in6_addr &) const;

	virtual pim_group_source_state *create_source_state(const inet6_addr &);
	virtual pim_group_source_rpt_state *create_source_rpt_state(const inet6_addr &);
	virtual pim_group_wildcard_state *create_wildcard_state();

	inet6_addr m_addr;
	pim_groupconf_node *m_conf;

	int m_refcount;

	void property_changed(node *, const char *);

	void report_forward_to_rp_failure();

	in6_addr m_rpaddr;
	rp_source m_rp_source;
	bool m_selfrp;

	rib_watcher<pim_group_node> m_rp_path;

	bool m_ssm;
	inet6_addr m_embedded_rpaddr;

	uint32_t m_rp_failure_count;
	const char *m_rp_failure_last_msg;
	timer<pim_group_node> m_rp_failure_report_timer;

	mfa_group *m_mfa_inst;

	pim_group_wildcard_state *m_wildcard;

	typedef std::pair<pim_group_source_state *, pim_group_source_rpt_state *> source_pair;
	typedef std::map<inet6_addr, source_pair> states;

	states m_states;

	friend class pim_group_source_state;
};

#endif


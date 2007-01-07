/*
 * Multicast Routing Daemon (MRD)
 *   mld/router.h
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

#ifndef _mrd_mld_router_h_
#define _mrd_mld_router_h_

#include <mrd/group.h>
#include <mrd/router.h>
#include <mrd/packet_buffer.h>
#include <mrd/address_set.h>
#include <mrd/node.h>
#include <mrd/timers.h>

#include <list>
#include <map>

#include <stdint.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <mrd/icmp.h>

class interface;
class group_interface;

class intfconf;

struct mldv1;
struct mldv2_report;

class mld_interface;
class mld_group_interface;
class mld_group;

class mld_intfconf_node : public intfconf_node {
public:
	mld_intfconf_node(intfconf *);

	bool check_startup();

	bool fill_defaults();

	bool set_property(const char *, const char *);

	uint32_t robustness() const;
	uint32_t query_interval() const;
	uint32_t query_response_interval() const;
	uint32_t mali() const;
	uint32_t other_querier_present_timeout() const;
	uint32_t startup_query_interval() const;
	uint32_t startup_query_count() const;
	uint32_t last_listener_query_interval() const;
	uint32_t last_listener_query_count() const;
	uint32_t last_listener_query_time() const;
	uint32_t unsolicited_report_interval() const;
	uint32_t older_version_querier_present_timeout() const;
	uint32_t version() const;

	bool querier() const;

	const std::set<inet6_addr> &signaling_filter() const;

	bool call_method(int id, base_stream &,
			 const std::vector<std::string> &);

	std::set<inet6_addr> m_signaling_filter;
};

class mld_groupconf_node : public groupconf_node {
public:
	mld_groupconf_node(groupconf *);

	bool fill_defaults();

	bool set_property(const char *, const char *);
};

class mld_interface : public interface_node {
public:
	mld_interface();
	~mld_interface();

	const char *description() const { return "MLD interface information"; }

	bool check_startup();
	void shutdown();

	void attached(interface *);

	bool send_mld_query(const in6_addr &);
	bool send_mld_query(const in6_addr &, const std::set<in6_addr> &);

	int get_current_version() const;

	bool is_querier() const;

	uint32_t get_querier_expiry_time() const;

	void start_querying();
	void change_is_querier(bool);

	mld_intfconf_node *conf() const;

	bool output_info(base_stream &, const std::vector<std::string> &) const;

private:
	friend class mld_router;

	void event(int, void *);

	bool send_mldv1_query(const in6_addr &);
	bool send_mldv2_query(const in6_addr &);

	void message_available(const in6_addr &, const in6_addr &, icmp6_hdr *, int);
	void icmp_message_available(const in6_addr &, const in6_addr &, icmp6_hdr *, int);

	void handle_mldv1_membership_report(const in6_addr &, mldv1 *);
	void handle_mldv2_membership_report(const in6_addr &, mldv2_report *, int);
	void handle_mldv1_membership_reduction(const in6_addr &, mldv1 *);
	void handle_membership_query(const in6_addr &);

	void handle_mode_change_for_group(int ver, const inet6_addr &reqsrc,
			const inet6_addr &grpaddr, int mode, const address_set &);

	void handle_send_query_timeout();
	void handle_other_querier_present_timeout();

	int mif_mld_version;
	bool mif_isquerier;

	uint32_t mif_query_count;

	inet6_addr mif_querier_addr;

	typedef timer<mld_interface> intf_timer;

	intf_timer mif_query_timer_id, mif_other_querier_present_timer_id;

	message_stats_node m_stats;

	void address_added_or_removed(bool, const inet6_addr &);
};

inline int mld_interface::get_current_version() const {
	return mif_mld_version;
}

inline bool mld_interface::is_querier() const {
	return mif_isquerier;
}

inline uint32_t mld_interface::get_querier_expiry_time() const {
	return mif_other_querier_present_timer_id.time_left();
}

inline mld_intfconf_node *mld_interface::conf() const {
	return (mld_intfconf_node *)owner()->conf()->get_child("mld");
}

class mld_group_interface : public group_interface {
public:
	mld_group_interface(mld_group *, mld_interface *);
	virtual ~mld_group_interface();

	const char *description() const { return "Multicast group local MLD information"; }

	virtual void refresh(const inet6_addr &, int, const address_set &);

	uint32_t time_left_to_expiry(bool withft) const;

	uint32_t uptime() const { return tval::now() - g_creation_time; }
	const inet6_addr &last_reporter() const { return g_last_reporter; }

protected:
	friend class mld_router;

	void output_info(base_stream &, bool) const;
	virtual void output_inner_info(base_stream &, bool) const;

	uint32_t mali() const;

	mld_group *g_owner;
	mld_interface *g_intf;
	tval g_creation_time;

	inet6_addr g_last_reporter;

	void delete_sources(const address_set &);
	void update_sources_timer(const address_set &, uint32_t = 0);

	void handle_filter_timer();
	void restart_filter_timer();

	virtual void send_mld_query(bool general, const address_set & = address_set());

	timer<mld_group_interface> g_filter_timer;
	timer<mld_group_interface> g_last_listener_timer;

	uint32_t g_last_listener_query_count;

	void start_fast_leave();

	void handle_source_timeout(in6_addr &);
	void handle_last_listener_query();

	typedef timer1<mld_group_interface, in6_addr> source_timer;

	std::vector<source_timer> g_sources_timers;

	address_set g_request_set;
};

class mld_group : public group_node {
public:
	mld_group(router *);
	~mld_group();

	const char *description() const { return "Active multicast group MLD information"; }

	void attached(group *);
	void dettached();
	void subscriptions_changed(const group_interface *,
			group_interface::event_type, const address_set &);
	group_interface *instantiate_group_interface(interface *);

	bool has_interest_in_group() const;

	mld_group_interface *local_oif(mld_interface *);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

private:
	friend class mld_router;

	node *m_conf;
};

/*!
 * \brief implements the core MLD protocol.
 *
 * `mld_router' implements both MLDv1 and MLDv2.
 */
class mld_router : public router, public icmp_handler {
public:
	mld_router();
	~mld_router();

	const char *description() const;

	bool check_startup();
	void shutdown();

	void add_interface(interface *);
	void remove_interface(interface *);

	void created_group(group *);
	void released_group(group *);

	intfconf_node *create_interface_configuration(intfconf *);
	groupconf_node *create_group_configuration(groupconf *);

	mld_interface *get_interface(int) const;

	mld_group *match(group *grp) const;

	bool send_icmp(const interface *, const in6_addr &,
		       icmp6_hdr *, uint16_t) const;

	void icmp_message_available(interface *, const in6_addr &,
				    const in6_addr &, icmp6_hdr *,
				    int len);

	bool call_method(int, base_stream &, const std::vector<std::string> &);
	bool output_info(base_stream &, const std::vector<std::string> &) const;

	message_stats_node &stats() { return m_stats; }

	base_stream &log_router_desc(base_stream &) const;

private:
	virtual mld_group *allocate_group();

	message_stats_node m_stats;
};

#endif


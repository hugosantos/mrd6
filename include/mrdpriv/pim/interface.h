/*
 * Multicast Routing Daemon (MRD)
 *   pim/interface.h
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

#ifndef _mrd_pim_interface_h_
#define _mrd_pim_interface_h_

#include <mrd/address.h>
#include <mrd/packet_buffer.h>
#include <mrd/interface.h>
#include <mrd/timers.h>
#include <mrd/node.h>

#include <mrdpriv/pim/def.h>

#include <list>

#include <netinet/in.h>

class interface;
class group;

class pim_group_node;
class pim_neighbour;

class pim_intfconf_node;

class pim_interface : public interface_node {
public:
	pim_interface();
	~pim_interface();

	const char *description() const { return "PIM interface information"; }

	bool check_startup();
	bool start_timers();
	void shutdown();

	void attached(interface *);

	bool am_dr() const { return !elected_dr; }

	uint32_t effective_propagation_delay() const;
	uint32_t effective_override_interval() const;
	bool lan_delay_enabled() const;

	bool send_local(sockaddr_in6 *dst, pim_message *msg, uint16_t len) const;
	bool send_all_routers(pim_message *msg, uint16_t len) const;

	bool send_join_prune(pim_joinprune_message *) const;
	bool send_assert(pim_assert_message *) const;

	void data_available(const sockaddr_in6 *src, const sockaddr_in6 *dst);

	bool call_method(int id, base_stream &,
			 const std::vector<std::string> &);

	pim_neighbour *get_neighbour(const in6_addr &) const;
	pim_neighbour *allocate_neighbour(const in6_addr &);

	enum state {
		NOT_READY = 0,
		LOCAL_READY,
		READY
	};

	state get_state() const { return intf_state; }

	const std::list<pim_neighbour *> &get_neighbours() const { return neighbours; }

	bool output_info(base_stream &, const std::vector<std::string> &) const;
	bool output_info(base_stream &, bool extended) const;

	pim_intfconf_node *conf() const;

	bool suppression_enabled() const;
	uint32_t suppressed_value() const;

private:
	void found_new_neighbour(pim_neighbour *);

	void event(int, void *);

	void handle_hello(const sockaddr_in6 *,
			pim_hello_message *, uint16_t len);
	void handle_joinprune(const sockaddr_in6 *,
			pim_joinprune_message *, uint16_t len);
	void handle_external_joinprune(const sockaddr_in6 *,
			pim_joinprune_message *, uint16_t len);

	void handle_join_wc_rpt(const inet6_addr &, const inet6_addr &,
			const address_set &, uint16_t, bool);
	void handle_join_wc_rpt(group *, const inet6_addr &,
				const address_set &, uint32_t, bool);

	void handle_join_source(const inet6_addr &, const inet6_addr &,
			uint32_t, bool);
	void handle_join_source(group *, const inet6_addr &, uint32_t, bool);

	void handle_join(const inet6_addr &, const inet6_addr &, uint32_t, bool);
	void handle_join(pim_group_node *, const inet6_addr &, uint32_t, bool);

	void handle_assert(const sockaddr_in6 *,
			pim_assert_message *msg, uint16_t len);
	void handle_bootstrap(const sockaddr_in6 *, const sockaddr_in6 *,
			pim_bootstrap_message *, uint16_t len);

	void handle_register(const sockaddr_in6 *, const sockaddr_in6 *);
	void handle_register_stop(const sockaddr_in6 *);
	void handle_candidate_rp_adv(const sockaddr_in6 *,
			pim_candidate_rp_adv_message *, uint16_t len);

	void send_hello();
	void send_hellox(uint16_t);

	bool flap_neighbour(base_stream &, const std::vector<std::string> &,
			    bool remove);

	void property_changed(node *n, const char *);

	/* Triggered whenever a Neighbour timer expires. */
	void neighbour_timed_out(pim_neighbour * &);
	/* Removes a Neighbour from this interface, notifying of the
	 * Neighbour loss. If elect is true, after removal the DR
	 * election mechanism is triggered. */
	void remove_neighbour(pim_neighbour *, bool elect);

	/* Implements the Lan-Prune-Delay mechanism. */
	void check_lan_delay();
	/* Implements the DR election mechanism. */
	void elect_subnet_dr();

	void update_hello_interval(uint32_t);

	typedef std::list<pim_neighbour *> neighbours_def;

	message_stats_node m_stats;

	uint32_t gen_id;
	timer<pim_interface> hello_timer_id;

	pim_neighbour *elected_dr;
	uint32_t m_propagation_delay, m_override_interval;
	bool m_landelay_enabled;

	neighbours_def neighbours;

	state intf_state;

	void address_added_or_removed(bool, const inet6_addr &);

	friend class pim_neighbour;
};

inline pim_intfconf_node *pim_interface::conf() const {
	return owner() ? (pim_intfconf_node *)owner()->conf()->get_child("pim") : 0;
}

#endif


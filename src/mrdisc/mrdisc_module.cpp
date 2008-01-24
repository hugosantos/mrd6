/*
 * Multicast Routing Daemon (MRD)
 *   mrdisc_module.cpp
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

#include <mrd/mrd.h>
#include <mrd/icmp.h>
#include <mrd/group.h>
#include <mrd/node.h>

#include <list>
#include <algorithm>
#include <cmath>

#include "mrdisc_def.h"

static const int MRDISC_MAX_INIT_ADV_DELAY = 2000;
static const int MRDISC_MAX_RESPONSE_DELAY = 2000;

enum {
	SolicitationCount = 0,
	AdvertisementCount,
	MessageCount
};

enum {
	RX = 0,
	TX,
	Bad
};

static const char *stats_descriptions[] = {
	"Solicitation",
	"Advertisement",
};

class mrdisc_module : public mrd_module, public node, public icmp_handler {
public:
	mrdisc_module(mrd *, void *);

	bool check_startup();
	void shutdown();

	void icmp_message_available(interface *, const in6_addr &,
				    const in6_addr &, icmp6_hdr *, int);

	void register_send_adv(interface *intf, int maxwhen);
	void event(int, void *);
	void send_unsolicited();
	void send_termination(interface *);
	void send_advert(interface *);
	void send_solicited(int &);

	int adv_jitter() const;
	int next_adv_interval() const;

	inet6_addr all_routers, all_snoopers;
	timer<mrdisc_module> m_unsolicited;

	int interface_count;

	typedef timer1<mrdisc_module, int> solicited_timer;
	typedef std::list<solicited_timer *> solicited_timers;
	solicited_timers m_solicited;

	property_def *adv_interval;

	message_stats_node m_stats;
};

module_entry(mrdisc, mrdisc_module);

mrdisc_module::mrdisc_module(mrd *m, void *p)
	: mrd_module(m, p), node(m, "mrdisc"),
	  m_unsolicited("mrdisc unsolicited", this,
			std::mem_fun(&mrdisc_module::send_unsolicited)),
	  m_stats(this, MessageCount, stats_descriptions) {
	all_routers = inet6_addr("ff02::2");
	all_snoopers = inet6_addr("ff02::6a");

	adv_interval = instantiate_property_u("adv-interval", 20000);

	interface_count = 0;
}

bool mrdisc_module::check_startup() {
	if (!adv_interval)
		return false;

	if (!m_stats.setup())
		return false;

	m_stats.disable_counter(SolicitationCount, TX);
	m_stats.disable_counter(AdvertisementCount, RX);

	if (!node::check_startup())
		return false;

	if (!g_mrd->add_child(this))
		return false;

	g_mrd->icmp().register_handler(MRDISC_ROUTER_SOLICITATION, this);
	g_mrd->icmp().require_mgroup(all_routers, true);

	return true;
}

void mrdisc_module::shutdown() {
	g_mrd->icmp().register_handler(MRDISC_ROUTER_SOLICITATION, 0);
	g_mrd->icmp().require_mgroup(all_routers, false);

	g_mrd->remove_child("msnip");
}

void mrdisc_module::icmp_message_available(interface *intf, const in6_addr &src,
					   const in6_addr &dst, icmp6_hdr *hdr,
					   int length) {
	if (hdr->icmp6_type != MRDISC_ROUTER_SOLICITATION)
		return;

	m_stats.counter(SolicitationCount, RX)++;

	if (!IN6_IS_ADDR_LINKLOCAL(&src) || !(dst == all_routers.address())) {
		m_stats.counter(SolicitationCount, Bad)++;
		return;
	}

	register_send_adv(intf, MRDISC_MAX_RESPONSE_DELAY);
}

void mrdisc_module::register_send_adv(interface *intf, int maxwhen) {
	/* timer is already running? */
	for (solicited_timers::const_iterator i =
			m_solicited.begin(); i != m_solicited.end(); ++i) {
		if ((*i)->argument() == intf->index())
			return;
	}

	solicited_timer *tmr = new solicited_timer("mrdisc solicitation timer",
						   this, std::mem_fun(&mrdisc_module::send_solicited),
						   intf->index());

	if (tmr) {
		tmr->start(mrd::get_randu32() % maxwhen);

		m_solicited.push_back(tmr);
	}
}

void mrdisc_module::event(int ev, void *ptr) {
	if (ev == mrd::InterfaceStateChanged) {
		interface *intf = (interface *)ptr;

		if (intf->up()) {
			register_send_adv(intf, MRDISC_MAX_INIT_ADV_DELAY);

			if (interface_count == 0) {
				m_unsolicited.start(next_adv_interval(), false);
			}

			interface_count ++;
		} else {
			send_termination(intf);

			if (interface_count == 1) {
				m_unsolicited.stop();
			}

			interface_count --;
		}
	} else {
		node::event(ev, ptr);
	}
}

void mrdisc_module::send_termination(interface *intf) {
	icmp6_hdr hdr;

	hdr.icmp6_type = MRDISC_ROUTER_TERMINATION;
	hdr.icmp6_code = 0;

	g_mrd->icmp().send_icmp(intf, all_snoopers, &hdr, 4);
}

void mrdisc_module::send_advert(interface *intf) {
	icmp6_hdr hdr;

	hdr.icmp6_type = MRDISC_ROUTER_ADVERTISEMENT;
	hdr.icmp6_code = adv_interval->get_unsigned() / 1000;

	const property_def *qi = 0, *rb = 0;

	if (intf->conf()->is_router_enabled("mld")) {
		qi = intf->conf()->get_child_property("mld", "query_interval");
		rb = intf->conf()->get_child_property("mld", "robustness");
	}

	/* query interval */
	hdr.icmp6_maxdelay = htons(qi ? (qi->get_unsigned() / 1000) : 0);
	/* robustness */
	hdr.icmp6_seq = htons(rb ? rb->get_unsigned() : 0);

	if (g_mrd->icmp().send_icmp(intf, all_snoopers, &hdr, sizeof(hdr))) {
		m_stats.counter(AdvertisementCount, TX)++;
	}
}

void mrdisc_module::send_unsolicited() {
	mrd::interface_list::const_iterator i;

	for (i = g_mrd->intflist().begin(); i != g_mrd->intflist().end(); ++i) {
		if (i->second->linklocals().empty() || !i->second->up())
			continue;

		send_advert(i->second);
	}

	m_unsolicited.start(next_adv_interval(), false);
}

void mrdisc_module::send_solicited(int &index) {
	for (solicited_timers::iterator i =
			m_solicited.begin(); i != m_solicited.end(); ++i) {
		if ((*i)->argument() == index) {
			interface *intf = g_mrd->get_interface_by_index(index);
			if (intf)
				send_advert(intf);

			delete *i;
			m_solicited.erase(i);

			return;
		}
	}
}

int mrdisc_module::adv_jitter() const {
	return (int)std::floor(adv_interval->get_unsigned() * 0.025 + 0.5);
}

int mrdisc_module::next_adv_interval() const {
	int jitter = adv_jitter();
	int base = adv_interval->get_unsigned();

	return base + (rand() % (2 * jitter)) - jitter;
}


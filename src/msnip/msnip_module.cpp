/*
 * Multicast Routing Daemon (MRD)
 *   msnip_module.cpp
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

#include "msnip_def.h"

class msnip_module : public mrd_module, public node, public icmp_handler {
public:
	msnip_module(mrd *, void *);

	bool check_startup();
	void shutdown();

	void icmp_message_available(interface *, const in6_addr &,
				    const in6_addr &, icmp6_hdr *, int);

	void refresh_source(interface *, const in6_addr &, uint16_t);
	void send_transmit(interface *, const in6_addr &, uint16_t);

	void send_single_transmit(interface *intf, const in6_addr &source,
					const in6_addr &grpaddr, bool active,
					int holdtime);

	void send_single_mrm(interface *intf, const in6_addr &dst,
				   msnip_mrm *mrm, int count) const;

	void source_timed_out(in6_addr &);

	void event(int, void *);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

	inet6_addr all_mld_routers;

	typedef timer1<msnip_module, in6_addr> source_timer;

	struct source_record {
		source_record(msnip_module *, const in6_addr &, interface *);

		source_timer tmr;
		interface *intf;
		uint16_t holdtime;
	};

	typedef std::list<source_record *> sources;

	sources::iterator get_source(const in6_addr &);

	sources m_sources;

	property_def *m_range;

	message_stats_node m_stats;
};

msnip_module::source_record::source_record(msnip_module *parent,
					   const in6_addr &src,
					   interface *_intf)
	: tmr("msnip source", parent,
	      std::mem_fun(&msnip_module::source_timed_out), src), intf(_intf) {}

module_entry(msnip, msnip_module);

enum {
	HISCount,
	MRMCount,
	MRMRecTransmitCount,
	MRMRecHoldCount,
	MessageCount
};

enum {
	RX = 0,
	TX,
	Bad
};

static const char *stats_descriptions[] = {
	"HIS",
	"MRM",
	"MRM-Rec-TX",
	"MRM-Rec-Hold",
};

msnip_module::msnip_module(mrd *m, void *p)
	: mrd_module(m, p), node(m, "msnip"),
	  m_stats(this, MessageCount, stats_descriptions) {
	all_mld_routers = inet6_addr("ff02::16");

	m_range = instantiate_property_a("range", inet6_addr("ff3e::/16"));
}

bool msnip_module::check_startup() {
	if (!m_range)
		return false;

	if (!m_stats.setup())
		return false;

	m_stats.disable_counter(HISCount, TX);
	m_stats.disable_counter(MRMCount, RX);

	m_stats.disable_counter(MRMRecTransmitCount, RX);
	m_stats.disable_counter(MRMRecHoldCount, RX);

	if (!node::check_startup())
		return false;

	if (!g_mrd->add_child(this))
		return false;

	g_mrd->register_startup(this);

	return true;
}

void msnip_module::shutdown() {
	g_mrd->interested_in_active_states(this, false);

	g_mrd->icmp().register_handler(MSNIP_HIS_REPORT, 0);
	g_mrd->icmp().require_mgroup(all_mld_routers, false);

	g_mrd->remove_child("msnip");
}

void msnip_module::icmp_message_available(interface *intf, const in6_addr &src,
					  const in6_addr &dst, icmp6_hdr *hdr,
					  int length) {
	if (!(dst == all_mld_routers.address()))
		return;

	if (hdr->icmp6_type == MSNIP_HIS_REPORT) {
		m_stats.counter(HISCount, RX)++;

		uint16_t holdtime = ntohs(hdr->icmp6_maxdelay) * 1000;

		if (should_log(MESSAGE_SIG))
			log().xprintf("(MSNIP) Received a HIS from %{addr} in "
				      "%s with holdtime %u\n", src,
				      intf->name(), (uint32_t)holdtime);

		refresh_source(intf, src, holdtime);
	}
}

msnip_module::sources::iterator msnip_module::get_source(const in6_addr &src) {
	/* XXX linear search for now */

	for (sources::iterator i = m_sources.begin(); i != m_sources.end(); ++i) {
		if ((*i)->tmr.argument() == src) {
			return i;
		}
	}

	return m_sources.end();
}

void msnip_module::refresh_source(interface *intf, const in6_addr &src,
				  uint16_t holdtime) {
	sources::iterator i = get_source(src);
	if (i != m_sources.end()) {
		if (holdtime == 0) {
			delete *i;
			m_sources.erase(i);
		} else {
			int diff = ((int)holdtime) - (*i)->tmr.time_left();
			if (diff < 1000) {
				/* only allow a refresh every second */
				return;
			}

			(*i)->tmr.update(holdtime, true);
			send_transmit(intf, src, holdtime);
		}
		return;
	}

	/* source not found */

	if (should_log(DEBUG))
		log().xprintf("(MSNIP) new source %{addr} with holdtime %u\n",
			      src, (uint32_t)holdtime);

	source_record *rec = new source_record(this, src, intf);

	if (rec) {
		rec->holdtime = holdtime;

		rec->tmr.start(holdtime, true);
		send_transmit(intf, src, holdtime);

		m_sources.push_back(rec);
	}
}

/* local buffer, should share this with rest */
static uint8_t buffer[1500];

void msnip_module::send_transmit(interface *intf, const in6_addr &src,
				 uint16_t holdtime) {
	/* iterate over groups */
	mrd::group_list::const_iterator i = g_mrd->group_table().begin();

	msnip_mrm *mrm = (msnip_mrm *)buffer;

	mrm->icmp6_type = MSNIP_MRM_REPORT;
	mrm->icmp6_code = 0; /* dst count */
	mrm->icmp6_maxdelay = htons(holdtime / 1000); /* holdtime */
	mrm->icmp6_seq = 0;

	int index = 0;

	int max_index = std::max(255, (int)((1280 - sizeof(msnip_mrm)) / (4 + sizeof(in6_addr))));

	for (; i != g_mrd->group_table().end(); ++i) {
		if (!m_range->get_address().matches(i->first))
			continue;

		if (!i->second->has_downstream_interest(src))
			continue;

		mrm->records[index].rectype = MSNIP_TRANSMIT;
		memset(mrm->records[index].resv, 0, sizeof(mrm->records[index].resv));

		mrm->records[index].address = i->first;

		index ++;
		if (index == max_index) {
			/* flush message, start over */
			send_single_mrm(intf, src, mrm, index);
			index = 0;
		}
	}

	if (index > 0) {
		send_single_mrm(intf, src, mrm, index);
	}
}

void msnip_module::send_single_mrm(interface *intf, const in6_addr &dst,
				   msnip_mrm *mrm, int count) const {
	int length = sizeof(msnip_mrm) + (4 + sizeof(in6_addr)) * count;

	mrm->icmp6_code = count;

	if (g_mrd->icmp().send_icmp(intf, dst, 0, mrm, length)) {
		if (should_log(MESSAGE_SIG)) {
			if (count == 1) {
				log().xprintf(
					"(MSNIP) Sent MRM to %{addr} with %s\n",
					dst, mrm->records[0].rectype == MSNIP_TRANSMIT ?
						"Transmit" : "Hold");
			} else {
				log().xprintf(
					"(MSNIP) Sent MRM to %{addr} with %i "
					"records\n", dst, count);
			}
		}

		m_stats.counter(MRMCount, TX)++;

		for (int i = 0; i < count; i++) {
			if (mrm->records[i].rectype == MSNIP_TRANSMIT)
				m_stats.counter(MRMRecTransmitCount, TX)++;
			else
				m_stats.counter(MRMRecHoldCount, TX)++;
		}
	}
}

void msnip_module::send_single_transmit(interface *intf, const in6_addr &source,
					const in6_addr &grpaddr, bool active,
					int holdtime) {
	msnip_mrm *mrm = (msnip_mrm *)buffer;

	mrm->icmp6_type = MSNIP_MRM_REPORT;
	mrm->icmp6_code = 0; /* dst count */
	mrm->icmp6_maxdelay = htons(holdtime / 1000); /* holdtime */
	mrm->icmp6_seq = 0;

	mrm->records[0].rectype = active ? MSNIP_TRANSMIT : MSNIP_HOLD;
	memset(mrm->records[0].resv, 0, sizeof(mrm->records[0].resv));

	mrm->records[0].address = grpaddr;

	send_single_mrm(intf, source, mrm, 1);
}

void msnip_module::source_timed_out(in6_addr &src) {
	sources::iterator i = get_source(src);

	/* assert(i != m_sources.end()); */

	if (should_log(DEBUG))
		log().xprintf("(MNSIP) source timed out %{addr}\n", src);

	delete *i;
	m_sources.erase(i);
}

void msnip_module::event(int id, void *ptr) {
	if (id == mrd::ActiveStateNotification) {
		mrd::active_state_report *rep = (mrd::active_state_report *)ptr;

		if (!m_range->get_address().matches(rep->group_instance->id()))
			return;

		msnip_module::sources::iterator i = get_source(rep->source_address);
		if (i != m_sources.end()) {
			send_single_transmit((*i)->intf, rep->source_address,
					     rep->group_instance->id(),
					     rep->active, (*i)->holdtime);
		}
	} else if (id == mrd::StartupEvent) {
		g_mrd->interested_in_active_states(this, true);

		g_mrd->icmp().register_handler(MSNIP_HIS_REPORT, this);
		g_mrd->icmp().require_mgroup(all_mld_routers, true);
	} else {
		node::event(id, ptr);
	}
}

bool msnip_module::output_info(base_stream &os,
			       const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	for (sources::const_iterator i
		= m_sources.begin(); i != m_sources.end(); ++i) {
		os.xprintf("%{addr} in %s for %{duration}\n",
			   (*i)->tmr.argument(), (*i)->intf->name(),
			   (*i)->tmr.time_left_d());
	}

	return true;
}


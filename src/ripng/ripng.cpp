/*
 * Multicast Routing Daemon (MRD)
 *   ripng.cpp
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
#include <mrd/router.h>
#include <mrd/interface.h>

#include <errno.h>
#include <netinet/ip6.h>

struct ripng_header {
	uint8_t command;
	uint8_t version;
	uint16_t zero;
};

struct ripng_rte {
	in6_addr prefix;
	uint16_t route_tag;
	uint8_t prefixlen;
	uint8_t metric;
};

enum {
	RIPNG_REQUEST	= 1,
	RIPNG_RESPONSE	= 2,
};

static const int RIP_INFINITY = 16;
static const int HoldTime = 60000;

class ripng_module : public mrd_module {
public:
	ripng_module(mrd *, void *);

	bool check_startup();
	void shutdown();
};

module_entry(ripng, ripng_module);

class ripng_router : public router, public mrib_origin {
public:
	ripng_router();

	bool check_startup();
	void shutdown();

	const char *description() const { return "RIPng"; }

	void add_interface(interface *);
	void remove_interface(interface *);

	struct ripng_prefix : public mrib_def::prefix {
		ripng_prefix(ripng_router *owner)
			: mrib_def::prefix(owner), metric(16) {}
		tval lastupdate;
		int metric;
	};

	void prefix_added(const inet6_addr &, mrib_def::metric_def, const mrib_def::prefix &);
	void prefix_lost(const inet6_addr &, mrib_def::metric_def, const mrib_def::prefix &);

	void return_prefix(mrib_def::prefix *);

private:
	void data_available(uint32_t);

	void send_table(interface * &);
	void send_request(interface *);
	void broadcast(ripng_header *, uint16_t);

	void garbage_collect();

	socket6<ripng_router> m_sock;

	sockaddr_in6 m_ripnggrp;

	typedef timer1<ripng_router, interface *> intf_timer;

	std::vector<intf_timer> m_intftimers;

	timer<ripng_router> m_garbcol_timer;
};

ripng_router *ripng = 0;

ripng_module::ripng_module(mrd *m, void *v)
	: mrd_module(m, v) {
}

bool ripng_module::check_startup() {
	if (ripng)
		return false;
	ripng = new ripng_router();
	if (!ripng || !m_mrd->register_router(ripng)) {
		delete ripng;
		ripng = 0;
		return false;
	}
	return true;
}

void ripng_module::shutdown() {
	if (ripng) {
		m_mrd->unregister_router(ripng);
		ripng->shutdown();
		delete ripng;
		ripng = 0;
	}
}

ripng_router::ripng_router()
	: router("ripng"),
	  m_sock("ripng sock", this, std::mem_fun(&ripng_router::data_available)),
	  m_garbcol_timer("ripng garbage collector", this,
		std::mem_fun(&ripng_router::garbage_collect), 30000, true) {

	m_ripnggrp = inet6_addr("ff02::9").as_sockaddr();
	m_ripnggrp.sin6_port = htons(522);
}

bool ripng_router::check_startup() {
	if (!router::check_startup())
		return false;

	int sock = socket(PF_INET6, SOCK_DGRAM, 0);
	if (sock < 0)
		return false;

	sockaddr_in6 local;
	memset(&local, 0, sizeof(local));
	local.sin6_family = AF_INET6;
	local.sin6_port = htons(522);

	if (bind(sock, (sockaddr *)&local, sizeof(local)) < 0) {
		if (should_log(WARNING))
			log().perror("Failed to bind");
		close(sock);
		return false;
	}

	if (!m_sock.register_fd(sock)) {
		close(sock);
		return false;
	}

	if (!m_sock.enable_mc_loop(false))
		return false;

	g_mrd->mrib().install_listener(this);

	m_garbcol_timer.start();

	return true;
}

void ripng_router::shutdown() {
	g_mrd->mrib().origin_lost(this);

	m_sock.unregister();
}

void ripng_router::garbage_collect() {
	tval now = tval::now();

	std::list<ripng_prefix *> removal;

	mrib_def::visitor v;

	if (!g_mrd->mrib().visit_origin(v, this))
		return;

	do {
		ripng_prefix *pinfo = (ripng_prefix *)v.entry();

		int32_t diff = now - pinfo->lastupdate;

		if (pinfo->metric < RIP_INFINITY) {
			if (diff >= (3 * HoldTime)) {
				pinfo->metric = RIP_INFINITY;
				pinfo->lastupdate = now;
			}
		} else if (pinfo->metric == RIP_INFINITY) {
			if (diff >= (2 * HoldTime)) {
				removal.push_back(pinfo);
			}
		}
	} while (g_mrd->mrib().visit_next(v));

	for (std::list<ripng_prefix *>::iterator i = removal.begin();
					i != removal.end(); ++i) {
		g_mrd->mrib().remove_prefix(*i);
	}
}

void ripng_router::add_interface(interface *intf) {
	if (!m_sock.join_mc(intf, m_ripnggrp.sin6_addr)) {
		if (should_log(WARNING))
			log().xprintf("Failed to join ff02::9 in %s, reason: %s",
				      intf->name(), strerror(errno));
	} else {
		send_request(intf);
	}

	std::string timername = "ripng timer (";
	timername += intf->name();
	timername += ")";

	m_intftimers.push_back(intf_timer(timername, this,
				std::mem_fun(&ripng_router::send_table),
				intf, HoldTime / 2, true));

	m_intftimers.back().start(true);
}

void ripng_router::remove_interface(interface *intf) {
	m_sock.leave_mc(intf, m_ripnggrp.sin6_addr);

	for (std::vector<intf_timer>::iterator i = m_intftimers.begin(); i != m_intftimers.end(); ++i) {
		if (i->argument() == intf) {
			m_intftimers.erase(i);
			break;
		}
	}
}

static uint8_t buffer[2048];

void ripng_router::prefix_added(const inet6_addr &prefix, mrib_def::metric_def metric,
				const mrib_def::prefix &pfrec) {
	if (should_log(INTERNAL_FLOW))
		log().xprintf("prefix_added %{Addr} metric %i flags %i\n",
			      prefix, (int)metric, (int)pfrec.flags);

	if (pfrec.flags & mrib_def::prefix::NO_EXPORT)
		return;

	mrib_def::prefix *p = g_mrd->mrib().get_prefix(prefix, this);
	if (p)
		g_mrd->mrib().remove_prefix(p);

	/* Triggered update */

	ripng_header *hdr = (ripng_header *)buffer;
	hdr->command = RIPNG_RESPONSE;
	hdr->version = 1;
	hdr->zero = 0;

	ripng_rte *rte = (ripng_rte *)(buffer + sizeof(ripng_header));
	rte->prefix = prefix.addr;
	rte->route_tag = 0;
	rte->prefixlen = prefix.prefixlen;
	rte->metric = 1;

	broadcast(hdr, sizeof(ripng_header) + sizeof(ripng_rte));
}

void ripng_router::prefix_lost(const inet6_addr &prefix, mrib_def::metric_def metric,
			       const mrib_def::prefix &pfrec) {
	/* XXX unimplemented */
}

void ripng_router::return_prefix(mrib_def::prefix *p) {
	delete p;
}

void ripng_router::send_request(interface *intf) {
	ripng_header hdr;
	hdr.command = RIPNG_REQUEST;
	hdr.version = 1;
	hdr.zero = 0;

	m_sock.sendto(&hdr, sizeof(hdr), &m_ripnggrp, intf->localaddr());
}

void ripng_router::broadcast(ripng_header *hdr, uint16_t len) {
	for (std::vector<intf_timer>::const_iterator i =
			m_intftimers.begin(); i != m_intftimers.end(); ++i) {
		m_sock.sendto(hdr, len, &m_ripnggrp, i->argument()->localaddr());
	}
}

void ripng_router::send_table(interface * &intf) {
	ripng_header *hdr = (ripng_header *)buffer;
	hdr->command = RIPNG_RESPONSE;
	hdr->version = 1;
	hdr->zero = 0;

	ripng_rte *rte = (ripng_rte *)(buffer + sizeof(ripng_header));

	int count = 0;
	int avail = intf->mtu() - sizeof(ripng_header) - sizeof(ip6_hdr);
	int max = avail / sizeof(ripng_rte);

	mrib_def::visitor v;

	if (!g_mrd->mrib().visit_best_metric(v))
		return;

	do {
		mrib_def::prefix *pinfo = v.entry();

		if (pinfo->flags & mrib_def::prefix::NO_EXPORT)
			continue;

		if (pinfo->intf == intf)
			continue;

		if (count == max) {
			m_sock.sendto(hdr, sizeof(hdr) + count * sizeof(ripng_rte),
					&m_ripnggrp, intf->localaddr());
			rte = (ripng_rte *)(buffer + sizeof(ripng_header));
			count = 0;
		}

		int metric = 1;
		if (pinfo->owner == this)
			metric = pinfo->metric;

		rte->prefix = v.addr().addr;
		rte->route_tag = 0;
		rte->prefixlen = v.addr().prefixlen;
		rte->metric = metric;

		rte++;
		count++;
	} while (g_mrd->mrib().visit_next(v));

	if (count) {
		m_sock.sendto(hdr, sizeof(hdr) + count * sizeof(ripng_rte),
					&m_ripnggrp, intf->localaddr());
	}
}

void ripng_router::data_available(uint32_t) {
	sockaddr_in6 from;

	int res = m_sock.recvfrom(buffer, sizeof(buffer), &from);
	if (res <= 0) {
		// XXX
		return;
	}

	/* ignore messages from self */
	if (g_mrd->has_address(from.sin6_addr))
		return;

	if (ntohs(from.sin6_port) != 522)
		return;

	if (res < (int)sizeof(ripng_header))
		return;

	if (((res - sizeof(ripng_header)) % sizeof(ripng_rte)) != 0)
		return;

	interface *intf = get_interface_by_index(from.sin6_scope_id);
	if (!intf)
		return;

	ripng_header *hdr = (ripng_header *)buffer;
	if (hdr->version != 1 && hdr->zero != 0)
		return;

	if (hdr->command == RIPNG_REQUEST) {
		send_table(intf);
	} else if (hdr->command == RIPNG_RESPONSE) {
		ripng_rte *rte = (ripng_rte *)(buffer + sizeof(ripng_header));

		int rtecount = (res - sizeof(ripng_header)) / sizeof(ripng_rte);

		for (int i = 0; i < rtecount; i++, rte++) {
			if (rte->metric < 1 || rte->metric > 16)
				continue;
			if (rte->prefixlen > 128)
				continue;
			inet6_addr prefix(rte->prefix, rte->prefixlen);
			if (prefix.type() & inet6_addr::multicast)
				continue;

			mrib_def::prefix *ex = g_mrd->mrib().get_prefix(prefix, this);

			int metric = rte->metric + 1;

			if (ex) {
				ripng_prefix *rpi = (ripng_prefix *)ex;

				if (rpi->metric >= metric) {
					rpi->lastupdate = tval::now();
					if (metric < rpi->metric) {
						rpi->metric = metric;
						rpi->nexthop = from.sin6_addr;
						rpi->intf = intf;
					}
				} else if (rte->metric == RIP_INFINITY) {
					if (rpi->nexthop == from.sin6_addr
						&& rpi->metric < RIP_INFINITY) {
						rpi->lastupdate = tval::now();
						rpi->metric = rte->metric;
					}
				} else {
					/* dont mrib::update_prefix */
					continue;
				}

				g_mrd->mrib().update_prefix(rpi);

				continue;
			}

			if (metric < RIP_INFINITY) {
				ripng_prefix *pinfo = new ripng_prefix(this);
				if (pinfo) {
					pinfo->distance = 120;
					pinfo->metric = metric;
					pinfo->nexthop = from.sin6_addr;
					pinfo->lastupdate = tval::now();
					pinfo->intf = intf;
					pinfo->metric = metric;
					g_mrd->mrib().install_prefix(prefix, pinfo);
				}
			}
		}
	}
}


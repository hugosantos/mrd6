/*
 * Multicast Routing Daemon (MRD)
 *  bsd/rib.h 
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

#ifndef _mrd_bsd_rib_h_
#define _mrd_bsd_rib_h_

#include <list>
#include <map>
#include <mrd/mrd.h>
#include <mrd/rib.h>
#include <mrd/timers.h>

struct rt_msghdr;
struct if_msghdr;
struct ifa_msghdr;
struct rt_addrinfo;

class bsd_rib : public rib_def {
public:
	bsd_rib();

	bool check_startup();
	void shutdown();

	void check_initial_interfaces();

	bool lookup_prefix(const in6_addr &, lookup_result &) const;

	void process_messages(rt_msghdr *, int len);
	void process_if_msg(if_msghdr *);
	void process_ifa_msg(int, ifa_msghdr *, bool);
	void process_addrinfo(int, rt_addrinfo *, bool);

	bool fill_lookup_result(lookup_result &, rt_msghdr *) const;

	void data_pending(uint32_t);
	void event_pending(rt_msghdr *);

	rt_msghdr *read_until(unsigned) const;

	int rtsock;
	socket0<bsd_rib> evsock;
	mutable uint32_t rtseq;
};

#endif


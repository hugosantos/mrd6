/*
 * Multicast Routing Daemon (MRD)
 *   unicast_route.h
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

#ifndef _mrd_linux_unicast_route_h_
#define _mrd_linux_unicast_route_h_

#include <mrd/mrd.h>
#include <mrd/rib.h>
#include <mrd/timers.h>

#ifdef __STRICT_ANSI__
#undef __STRICT_ANSI__
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#define __STRICT_ANSI__
#else
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include <map>
#include <list>

struct netlink_msg;

/*!
 * \brief Implements the `unicast_router' interface in Linux.
 */
class linux_unicast_router : public rib_def {
public:
	linux_unicast_router();
	~linux_unicast_router();

	bool check_startup();
	void shutdown();

	void check_initial_interfaces();

	bool set_property(const char *, const char *);

	void do_dump(int);

private:
	bool send_nlmsg(const netlink_msg *, netlink_msg *) const;
	bool lookup_prefix(const in6_addr &, lookup_result &) const;

	void notify_changes();
	void data_available(uint32_t);
	int process_message();

	void dump_request(int);

	void handle_route_event(bool isnew, nlmsghdr *);
	void handle_intf_event(bool isnew, nlmsghdr *);
	void handle_addr_event(bool isnew, nlmsghdr *);

	void parse_prefix_rec(rtattr *tb[], int, int, lookup_result &) const;

	uint8_t *buffer;
	property_def *bufferlen;

	int rt_sock;
	socket0<linux_unicast_router> rt_bcast_sock;
	bool rt_dumping;

	uint32_t rt_nlseq;
};

#endif


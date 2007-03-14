/*
 * Multicast Routing Daemon (MRD)
 *   mrd/icmp.h
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

#ifndef _mrd_icmp_h_
#define _mrd_icmp_h_

#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <map>

class interface;

class icmp_handler {
public:
	virtual ~icmp_handler() {}

	virtual void icmp_message_available(interface *, const in6_addr &,
					    const in6_addr &, icmp6_hdr *,
					    int) = 0;
};

class icmp_base {
public:
	virtual ~icmp_base() {}

	virtual bool check_startup() = 0;
	virtual void shutdown() = 0;

	bool send_icmp(const in6_addr &dst, icmp6_hdr *, uint16_t) const;
	bool send_icmp(const interface *intf, const in6_addr &dst,
		       icmp6_hdr *, uint16_t) const;
	bool send_icmp(const interface *intf, const in6_addr &dst,
		       int rta, icmp6_hdr *, uint16_t) const;
	bool send_icmp(const interface *, const in6_addr &,
		       const in6_addr &, icmp6_hdr *, uint16_t) const;

	virtual bool send_icmp(const interface *, const in6_addr &,
			       const in6_addr &, int, icmp6_hdr *,
			       uint16_t) const = 0;

	bool register_handler(int type, icmp_handler *);

	void require_mgroup(const in6_addr &, bool);

	virtual void added_interface(interface *) = 0;
	virtual void removed_interface(interface *) = 0;

protected:
	void icmp_message_available(interface *, const in6_addr &,
				    const in6_addr &, icmp6_hdr *, int);

	virtual void registration_changed();
	virtual void internal_require_mgroup(const in6_addr &, bool) = 0;

	typedef std::map<int, icmp_handler *> handlers;
	handlers m_handlers;

	typedef std::map<in6_addr, int> mgroups;
	mgroups m_mgroups;
};

#endif


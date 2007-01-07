/*
 * Multicast Routing Daemon (MRD)
 *   mrdpriv/icmp_inet6.h
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

#ifndef _mrd_icmp_inet6_h_
#define _mrd_icmp_inet6_h_

#include <mrd/mrd.h>
#include <mrd/icmp.h>

class icmp_inet6 : public icmp_base {
public:
	icmp_inet6();

	bool check_startup();
	void shutdown();

	bool send_icmp(const interface *, const in6_addr &,
		       const in6_addr &, int, icmp6_hdr *, uint16_t) const;

	void added_interface(interface *);
	void removed_interface(interface *);

	void data_available(uint32_t);

	bool apply_icmp_filter();

	void registration_changed();
	void internal_require_mgroup(const in6_addr &, bool);

	mutable socket6<icmp_inet6> m_icmpsock;
};

#endif


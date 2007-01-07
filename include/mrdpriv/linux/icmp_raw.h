/*
 * Multicast Routing Daemon (MRD)
 *   mrdpriv/linux/icmp_raw.h
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

#ifndef _mrd_linux_icmp_raw_h_
#define _mrd_linux_icmp_raw_h_

#include <mrd/mrd.h>
#include <mrdpriv/icmp_inet6.h>

class linux_icmp_raw : public icmp_inet6 {
public:
	linux_icmp_raw();

	bool check_startup();
	void shutdown();

	void added_interface(interface *);
	void removed_interface(interface *);

	void data_available(uint32_t);

	void registration_changed();
	void internal_require_mgroup(const in6_addr &, bool);

	mutable socket0<linux_icmp_raw> m_rawicmpsock;
};

#endif


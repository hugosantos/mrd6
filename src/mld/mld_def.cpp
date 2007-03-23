/*
 * Multicast Routing Daemon (MRD)
 *   mld_def.cpp
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

#include <mrd/interface.h>
#include <mrd/node.h>
#include <mrdpriv/mld/def.h>
#include <mrdpriv/mld/router.h>

void mldv1::construct(const in6_addr &addr, int _type, mld_intfconf_node *n) {
	type = _type;
	code = 0;
	checksum = 0;

	/* General Query
	 *   max_response_delay = [Query Response Interval]
	 * Multicast-Address-Specific Query
	 *   max_response_delay = [Last Listener Query Interval] */

	if (IN6_IS_ADDR_UNSPECIFIED(&addr))
		maxdelay = hton((uint16_t)n->query_response_interval());
	else
		maxdelay = hton((uint16_t)n->last_listener_query_interval());

	data = hton((uint16_t)0);

	mcaddr = addr;
}

void mldv1_query::construct(const in6_addr &mcaddr, mld_intfconf_node *node) {
	mldv1::construct(mcaddr, MLD_LISTENER_QUERY, node);
}

void mldv2_query::construct(const in6_addr &addr, int type, mld_intfconf_node *n) {
	mldv1::construct(addr, type, n);

	qrv = n->robustness();
	suppress = 0;
	resv2 = 0;

	uint32_t qis = n->query_interval() / 1000;

	if (qis < 128)
		qqic = qis;
	else {
		int exp = 0;

		while ((qis >> (exp+3)) > 0x1f)
			exp++;

		qis >>= exp+3;
		qis -= 0x10;

		qqic = 0x80 | (exp << 4) | qis;
	}

	nsrcs = hton((uint16_t)0);
}


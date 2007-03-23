/*
 * Multicast Routing Daemon (MRD)
 *   mld/def.h
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

#ifndef _mrd_mdl_def_h_
#define _mrd_mdl_def_h_

#include <mrd/support/uint_n.h>

#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

class node;
class mld_intfconf_node;

#ifndef MLD_LISTENER_QUERY
#define MLD_LISTENER_QUERY		130
#endif

#ifndef MLD_LISTENER_REPORT
#define MLD_LISTENER_REPORT		131
#endif

#ifndef MLD_LISTENER_REDUCTION
#define MLD_LISTENER_REDUCTION		132
#endif

#ifndef MLDv2_LISTENER_REPORT
#define MLDv2_LISTENER_REPORT		143
#endif

#ifndef MLDv2_LISTENER_REPORT_OLD
#define MLDv2_LISTENER_REPORT_OLD	206
#endif

extern in6_addr in6addr_linkscope_allnodes;

#define MLD_SSM_MODE_INCLUDE		1
#define MLD_SSM_MODE_EXCLUDE		2
#define MLD_SSM_CHANGE_TO_INCLUDE	3
#define MLD_SSM_CHANGE_TO_EXCLUDE	4
#define MLD_SSM_ALLOW_SOURCES		5
#define MLD_SSM_BLOCK_SOURCES		6

class interface;

/*!
 * \brief MLD base header.
 */
struct mld_base {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;

	uint16n_t maxdelay;
	uint16n_t data;
} __attribute__ ((packed));

struct mldv1 : mld_base {
	in6_addr mcaddr;

	int length() const { return sizeof(mldv1); }

	void construct(const in6_addr &, int type, mld_intfconf_node *);
} __attribute__ ((packed));

struct mldv1_query : mldv1 {
	void construct(const in6_addr &, mld_intfconf_node *);
} __attribute__ ((packed));

/*!
 * \brief MLDv2 Query header. derives from MLD header.
 */
struct mldv2_query : mldv1 {
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t qrv : 3, suppress : 1, resv2 : 4;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t resv2 : 4, suppress : 1, qrv : 3;
#else
#	error "your system endianness isn't supported yet"
#endif
	uint8_t qqic;
	uint16n_t nsrcs;
	in6_addr srcs[0];

	int length() const { return sizeof(mldv1) + 4 + ntoh(nsrcs) * sizeof(in6_addr); }

	void construct(const in6_addr &, int type, mld_intfconf_node *);
	void construct_query(const in6_addr &mca, mld_intfconf_node *conf) {
		construct(mca, MLD_LISTENER_QUERY, conf);
	}

} __attribute__ ((packed));

/*!
 * \brief A MLDv2 Multicast record. Contained in MLDv2 Report messages.
 */
struct mldv2_mrec {
	uint8_t type;
	uint8_t auxdatalen;
	uint16n_t nsrcs;
	in6_addr mca;

	in6_addr *sources() {
		return (in6_addr *)(((uint8_t *)this) + sizeof(*this));
	}

	mldv2_mrec *next() {
		return (mldv2_mrec *)
			(((uint8_t *)this) + sizeof(*this) +
				ntoh(nsrcs) * sizeof(in6_addr) + auxdatalen);
	}
} __attribute__ ((packed));

/*!
 * \brief A MLDv2 Report header. Derives from MLD base header.
 */
struct mldv2_report : mld_base {
	const uint16n_t &nmrecs() const { return data; }

	mldv2_mrec *mrecs() {
		return (mldv2_mrec *)(((uint8_t *)this) + sizeof(*this));
	}
} __attribute__ ((packed));

#endif


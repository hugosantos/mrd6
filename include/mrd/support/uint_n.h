/*
 * Multicast Routing Daemon (MRD)
 *   uint_n.h
 *
 * Copyright (C) 2007 Hugo Santos
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

#ifndef __uint_n__h
#define __uint_n__h

#include <netinet/in.h>

namespace priv {
	/* these are used just to use c++ type-matching
	 * capabilities through overriding */
	static inline uint16_t __host_to_net(uint16_t v) { return htons(v); }
	static inline uint32_t __host_to_net(uint32_t v) { return htonl(v); }

	static inline uint16_t __net_to_host(uint16_t v) { return ntohs(v); }
	static inline uint32_t __net_to_host(uint32_t v) { return ntohl(v); }

	template<typename _Base>
	struct uint_n {
		_Base __value;

		uint_n() : __value(0) {}

		_Base host() const { return __net_to_host(__value); }

		static uint_n<_Base> net(_Base v) {
			uint_n<_Base> u;
			u.__value = __host_to_net(v);
			return u;
		}
	} __attribute__ ((packed));
}

typedef priv::uint_n<uint16_t> uint16n_t;
typedef priv::uint_n<uint32_t> uint32n_t;

static inline uint16n_t hton(uint16_t value) { return uint16n_t::net(value); }
static inline uint32n_t hton(uint32_t value) { return uint32n_t::net(value); }

static inline uint16_t ntoh(uint16n_t value) { return value.host(); }
static inline uint32_t ntoh(uint32n_t value) { return value.host(); }

#endif

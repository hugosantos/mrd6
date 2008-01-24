/*
 * Multicast Routing Daemon (MRD)
 *   address.h
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

#ifndef _mrd_address_h_
#define _mrd_address_h_

#include <stdint.h>
#include <netinet/in.h>

#include <cstring>

#include <map>
#include <string>
#include <vector>

class base_stream;

static inline bool operator < (const in6_addr &a1, const in6_addr &a2) {
	return memcmp(a1.s6_addr, a2.s6_addr, 16) < 0;
}

static inline bool operator == (const in6_addr &a1, const in6_addr &a2) {
	return IN6_ARE_ADDR_EQUAL(&a1, &a2);
}

static inline int pnode_prefix_length(const in6_addr &p) {
	return sizeof(in6_addr) * 8;
}

static inline bool pnode_symbol_at(const in6_addr &p, int n) {
	return p.s6_addr[n / 8] & (0x80 >> (n & 0x07));
}

/*!
 * \class inet6_addr mrd/address.h
 * \brief provides an in6_addr + prefixlen abstraction and container.
 */
struct inet6_addr {
	inet6_addr();
	inet6_addr(const in6_addr &);
	inet6_addr(const in6_addr &, uint8_t prefixlen);
	inet6_addr(const inet6_addr &);
	explicit inet6_addr(const std::string &);
	explicit inet6_addr(const std::vector<char> &);

	static inet6_addr any() {
		return inet6_addr();
	}

	bool is_any() const {
		return IN6_IS_ADDR_UNSPECIFIED(&addr);
	}

	bool is_linklocal() const {
		return IN6_IS_ADDR_LINKLOCAL(&addr);
	}

	enum {
		multicast = 2,
		network = 4
	};

	unsigned type() const;

	inet6_addr prefix() const;

	bool operator < (const inet6_addr &) const;
	bool operator > (const inet6_addr &) const;
	bool operator == (const inet6_addr &) const;

	bool operator == (const in6_addr &rho) const {
		return IN6_ARE_ADDR_EQUAL(&addr, &rho);
	}

	inet6_addr &operator = (const inet6_addr &base) {
		set(base.address(), base.prefixlen);
		return *this;
	}

	inet6_addr &operator = (const in6_addr &base) {
		return (*this) = inet6_addr(base);
	}

	bool partial_match(const in6_addr &ma, uint8_t malen) const {
		uint8_t plen = prefixlen;
		const uint32_t *ap = (const uint32_t *)&addr;
		const uint32_t *bp = (const uint32_t *)&ma;
		while (plen >= 32) {
			if (*ap != *bp)
				return false;
			ap ++; bp ++;
			plen -= 32;
		}
		if (plen > 0) {
			uint32_t mask = 0xffffffff << (32 - plen);
			if ((ntohl(*ap) & mask) != (ntohl(*bp) & mask))
				return false;
		}
		return true;
	}

	bool matches(const in6_addr &ma, uint8_t malen = 128) const {
		if (prefixlen == 0) {
			return true;
		} else if (prefixlen == 128) {
			return IN6_ARE_ADDR_EQUAL(&addr, &ma);
		} else if (malen < prefixlen) {
			return false;
		}

		return partial_match(ma, malen);
	}

	bool matches(const inet6_addr &address) const {
		return matches(address.address(), address.prefixlen);
	}

	const in6_addr &address() const { return addr; }
	const in6_addr *address_p() const { return &addr; }

	std::string as_string() const;
	sockaddr_in6 as_sockaddr() const;

	char *print_string(char *, int) const;

	operator std::string () const { return as_string(); }
	operator in6_addr () const { return addr; }

	void set(const in6_addr &, uint8_t);

	bool set(const std::string &);

	static bool from_string(const std::string &, inet6_addr &);
	static void to_string(const inet6_addr &, std::string &);

	void apply_prefixlen();

	/* ptree-key implementing methods */
	friend int pnode_prefix_length(const inet6_addr &p) {
		return p.prefixlen;
	}

	friend bool pnode_symbol_at(const inet6_addr &p, int n) {
		return pnode_symbol_at(p.addr, n);
	}

	in6_addr addr;
	uint8_t prefixlen;
};

static inline const char *stream_type_format_parameter(const in6_addr &) {
	return "{addr}";
}

static inline const char *stream_type_format_parameter(const inet6_addr &) {
	return "{Addr}";
}

void stream_push_formated_type(base_stream &os, const in6_addr &);
void stream_push_formated_type(base_stream &os, const inet6_addr &);

#endif


/*
 * Multicast Routing Daemon (MRD)
 *   bgp/def.h
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

#ifndef _mrd_bgp_def_h_
#define _mrd_bgp_def_h_

#include <stdint.h>

#include <vector>
#include <algorithm>

#include <mrd/address.h>

class bgp_message {
public:
	bgp_message();
	bgp_message(uint8_t);
	bgp_message(const bgp_message &);
	virtual ~bgp_message();

	virtual bool decode(encoding_buffer &);
	virtual bool encode(encoding_buffer &) const;

	virtual uint16_t length() const { return len; }

	const char *type_name() const;

	uint16_t len;
	uint8_t type;
};

class bgp_open_message : public bgp_message {
public:
	bgp_open_message();
	bgp_open_message(const bgp_message &);

	virtual uint16_t length() const;

	bool decode(encoding_buffer &);
	bool encode(encoding_buffer &) const;

	uint8_t version;
	uint16_t as;
	uint16_t holdtime;
	uint32_t bgpid;

	enum {
		IPV6 = 2
	};

	enum {
		UNICAST = 1,
		MULTICAST,
		UNICAST_MULTICAST
	};

	typedef std::pair<uint16_t, uint8_t> capability;
	std::vector<capability> capabilities;
};

class bgp_as_path : public std::vector<uint16_t> {
public:
	bgp_as_path &prepend(uint16_t value) { insert(begin(), value); return *this; }
};

typedef std::pair<uint16_t, uint16_t> bgp_community;
typedef std::vector<bgp_community> bgp_communities;

class bgp_update_message : public bgp_message {
public:
	bgp_update_message();
	bgp_update_message(const bgp_message &);

	virtual uint16_t length() const;

	bool decode(encoding_buffer &);
	bool encode(encoding_buffer &) const;

	enum {
		IGP = 0,
		INCOMPLETE = 2
	};

	uint8_t origin;
	uint32_t localpref, med;

	bgp_as_path as_path;

	bgp_communities communities;

	std::vector<inet6_addr> nexthops;
	std::vector<inet6_addr> prefixes;
	std::vector<inet6_addr> unreach_prefixes;
};

class bgp_notification_message : public bgp_message {
public:
	bgp_notification_message();
	bgp_notification_message(const bgp_message &);

	virtual uint16_t length() const;

	bool decode(encoding_buffer &);
	bool encode(encoding_buffer &) const;

	uint8_t errorcode;
	uint8_t suberrorcode;
};

#endif


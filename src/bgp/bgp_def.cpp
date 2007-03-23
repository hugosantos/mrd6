/*
 * Multicast Routing Daemon (MRD)
 *   bgp_def.cpp
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

#include <mrd/log.h>
#include <mrd/packet_buffer.h>
#include <mrd/support/uint_n.h>

#include <mrdpriv/bgp/def.h>

enum {
	ORIGIN = 1,
	AS_PATH = 2,
	MULTI_EXIT_DISC = 4,
	LOCAL_PREF = 5,
	COMMUNITIES = 8,
	MP_REACH_NLRI = 14,
	MP_UNREACH_NLRI = 15
};

enum {
	CAPABILITY_NEGOTIATION = 2
};

enum {
	AS_SEQUENCE = 2
};

enum {
	IPV4_AFI = 1,
	IPV6_AFI = 2
};

enum {
	UNICAST_SAFI = 1,
	MULTICAST_SAFI = 2,
};

struct bgp_base_header {
	uint8_t marker[16];
	uint16n_t length;
	uint8_t type;
} __attribute__ ((packed));

static const uint8_t good_marker[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

bgp_message::bgp_message()
	: len(0), type(0) {
}

bgp_message::bgp_message(const bgp_message &msg)
	: len(msg.len), type(msg.type) {
}

bgp_message::bgp_message(uint8_t basetype)
	: len(19), type(basetype) {
}

bgp_message::~bgp_message() {}

bool bgp_message::decode(encoding_buffer &buff) {
	if (!buff.require(19))
		return false;

	bgp_base_header *h = (bgp_base_header *)buff.head();

	if (memcmp(h->marker, good_marker, 16) != 0)
		return false;

	len = ntoh(h->length);
	type = h->type;

	if (!buff.require(len))
		return false;

	buff.eat(19);

	return true;
}

bool bgp_message::encode(encoding_buffer &buff) const {
	if (!buff.tail_require(length()))
		return false;

	memcpy(buff.put(16), good_marker, 16);
	buff.put<uint16n_t>() = hton(length());
	buff.put<uint8_t>() = type;

	return true;
}

const char *bgp_message::type_name() const {
	switch (type) {
	case 1:
		return "OPEN";
	case 2:
		return "UPDATE";
	case 3:
		return "NOTIFICATION";
	case 4:
		return "KEEPALIVE";
	default:
		return "UNKNOWN";
	}
}

bgp_open_message::bgp_open_message()
	: bgp_message(1) {
	version = 4;
	as = 0;
	holdtime = 0;
	bgpid = 0;
}

bgp_open_message::bgp_open_message(const bgp_message &msg)
	: bgp_message(msg) {
}

uint16_t bgp_open_message::length() const {
	return bgp_message::length() + 9 + 1 + 8;
}

bool bgp_open_message::decode(encoding_buffer &b) {
	version = b.eat<uint8_t>();
	as = ntoh(b.eat<uint16n_t>());
	holdtime = ntoh(b.eat<uint16n_t>());
	bgpid = ntoh(b.eat<uint32n_t>());

	uint32_t extralen = b.eat<uint8_t>();

	for (uint32_t i = 0; i < extralen; ) {
		uint8_t type = b.eat<uint8_t>();
		uint8_t len = b.eat<uint8_t>();

		if (type == CAPABILITY_NEGOTIATION) {
			uint8_t code = b.eat<uint8_t>();
			uint32_t codelen = b.eat<uint8_t>();

			if (code == 1 && ((codelen % 4) == 0)) {
				for (uint32_t j = 0; j < codelen; j += 4) {
					uint16_t family = ntoh(b.eat<uint16n_t>());
					b.eat(1);
					uint8_t subfamily = b.eat<uint8_t>();
					capabilities.push_back(capability(family, subfamily));
				}
			} else {
				b.eat(codelen);
			}
		} else {
			b.eat(len);
		}

		i += len + 2;
	}

	return true;
}

bool bgp_open_message::encode(encoding_buffer &b) const {
	if (!bgp_message::encode(b))
		return false;
	b.put<uint8_t>() = version;
	b.put<uint16n_t>() = hton(as);
	b.put<uint16n_t>() = hton(holdtime);
	b.put<uint32n_t>() = hton(bgpid);

	if (capabilities.empty()) {
		b.put<uint8_t>() = 0;
	} else {
		b.put<uint8_t>() = 2 + (2 + 4 * capabilities.size());

		b.put<uint8_t>() = CAPABILITY_NEGOTIATION;
		b.put<uint8_t>() = 2 + 4 * capabilities.size();

		b.put<uint8_t>() = 1; // code
		b.put<uint8_t>() = 4 * capabilities.size();

		for (std::vector<capability>::const_iterator i = capabilities.begin();
				i != capabilities.end(); i++) {
			b.put<uint16n_t>() = hton(i->first);
			b.put<uint8_t>() = 0;
			b.put<uint8_t>() = i->second;
		}
	}

	return true;
}

bgp_update_message::bgp_update_message()
	: bgp_message(2) {
	origin = 2;
	localpref = 0;
	med = 0;
}

bgp_update_message::bgp_update_message(const bgp_message &msg)
	: bgp_message(msg) {
}

static void read_uint32(encoding_buffer &b, uint32_t *target, int len) {
	if (len == 4)
		(*target) = ntoh(b.eat<uint32n_t>());
	else
		b.eat(len);
}

bool bgp_update_message::decode(encoding_buffer &b) {
	uint16_t url = ntoh(b.eat<uint16n_t>());
	b.eat(url);

	uint32_t tpal = ntoh(b.eat<uint16n_t>());

	uint32_t i = 0;
	while (i < tpal) {
		uint8_t flags = b.eat<uint8_t>();
		uint8_t type = b.eat<uint8_t>();
		uint16_t len;

		if (flags & 0x10)
			len = ntoh(b.eat<uint16n_t>());
		else
			len = b.eat<uint8_t>();

		int avail;
		uint16_t family;
		uint8_t subfamily;

		switch (type) {
		case ORIGIN:
			origin = b.eat<uint8_t>();
			b.eat(len - 1);
			break;

		case AS_PATH:
			avail = len;
			while (avail >= 2) {
				uint8_t segtype = b.eat<uint8_t>();
				uint16_t seglen = b.eat<uint8_t>();
				if (segtype == AS_SEQUENCE) {
					for (uint16_t j = 0; j < seglen; j++)
						as_path.push_back(ntoh(b.eat<uint16n_t>()));
				} else {
					b.eat(2 * seglen);
				}
				avail -= 2 * seglen + 2;
			}
			b.eat(avail);
			break;

		case MULTI_EXIT_DISC:
			read_uint32(b, &med, len);
			break;

		case LOCAL_PREF:
			read_uint32(b, &localpref, len);
			break;

		case COMMUNITIES:
			for (uint8_t j = 0; j < len; j += 4)
				communities.push_back(bgp_community(ntoh(b.eat<uint16n_t>()),
								    ntoh(b.eat<uint16n_t>())));
			break;

		case MP_REACH_NLRI:
			family = ntoh(b.eat<uint16n_t>());
			subfamily = b.eat<uint8_t>();

			if (family == IPV6_AFI && subfamily == MULTICAST_SAFI) {
				// NextHop
				uint8_t nexthoplen = b.eat<uint8_t>();
				for (uint8_t j = 0; j < nexthoplen; j += 16) {
					in6_addr addr = b.eat<in6_addr>();
					nexthops.push_back(addr);
				}

				// Subnetwork
				uint8_t subnetlen = b.eat<uint8_t>();
				b.eat(subnetlen);

				// Prefixes
				int avail = len - 3 - nexthoplen - 1 - subnetlen - 1;
				while (avail > 0) {
					inet6_addr prefix;

					prefix.prefixlen = b.eat<uint8_t>();
					int plen = prefix.prefixlen / 8;
					if (prefix.prefixlen & 0x7) {
						plen++;
					}

					memcpy(&prefix.addr, b.eat(plen), plen);
					avail -= 1 + plen;

					prefixes.push_back(prefix);
				}
			} else {
				b.eat(len - 3);
			}
			break;

		case MP_UNREACH_NLRI:
			family = ntoh(b.eat<uint16n_t>());
			subfamily = b.eat<uint8_t>();

			if (family == IPV6_AFI && subfamily == MULTICAST_SAFI) {
				// Prefixes
				int avail = len - 3;
				while (avail > 0) {
					inet6_addr prefix;

					prefix.prefixlen = b.eat<uint8_t>();
					int plen = prefix.prefixlen / 8;
					if (prefix.prefixlen & 0x7)
						plen++;

					memcpy(&prefix.addr, b.eat(plen), plen);
					avail -= 1 + plen;

					unreach_prefixes.push_back(prefix);
				}
			} else {
				b.eat(len - 3);
			}
			break;

		default:
			b.eat(len);
			break;
		}

		i += len + 3 + ((flags & 0x10) ? 1 : 0);
	}

	return true;
}

uint16_t bgp_update_message::length() const {
	uint16_t length = bgp_message::length() + 2 + 2
		+ (3 + 1) // origin
		+ (3 + 2 + 2 * as_path.size()) // as_path
		+ (communities.empty() ? 0 : (3 + 4 * communities.size())) // communities
		+ (3 + 3 + (1 + 16 * nexthops.size()) + (1)); // mp_reach_nlri

	for (std::vector<inet6_addr>::const_iterator i = prefixes.begin();
						i != prefixes.end(); ++i) {
		length += i->prefixlen / 8;
		if (i->prefixlen & 0x7)
			length++;
		length++;
	}

	return length;
}

bool bgp_update_message::encode(encoding_buffer &b) const {
	if (!bgp_message::encode(b))
		return false;

	uint16_t len = length();
	len -= bgp_message::length();
	len -= 2 + 2;

	b.put<uint16n_t>() = hton((uint16_t)0);
	b.put<uint16n_t>() = hton(len);

	b.put<uint8_t>() = 0x40;
	b.put<uint8_t>() = ORIGIN;
	b.put<uint8_t>() = 1;
	b.put<uint8_t>() = origin;

	b.put<uint8_t>() = 0x40;
	b.put<uint8_t>() = AS_PATH;
	b.put<uint8_t>() = 2 + 2 * as_path.size();
	b.put<uint8_t>() = AS_SEQUENCE;
	b.put<uint8_t>() = as_path.size();
	for (bgp_as_path::const_iterator i = as_path.begin();
					i != as_path.end(); ++i)
		b.put<uint16n_t>() = hton(*i);

	if (!communities.empty()) {
		b.put<uint8_t>() = 0xc0;
		b.put<uint8_t>() = COMMUNITIES;
		b.put<uint8_t>() = 4 * communities.size();
		for (std::vector<bgp_community>::const_iterator i =
			communities.begin(); i != communities.end(); ++i) {
			b.put<uint16n_t>() = hton(i->first);
			b.put<uint16n_t>() = hton(i->second);
		}
	}

	b.put<uint8_t>() = 0x80;
	b.put<uint8_t>() = MP_REACH_NLRI;
	uint8_t &nlri_len = b.put<uint8_t>();
	nlri_len = 2 + 1 + (1 + 16 * nexthops.size()) + 1;

	b.put<uint16n_t>() = hton((uint16_t)IPV6_AFI);
	b.put<uint8_t>() = MULTICAST_SAFI;

	b.put<uint8_t>() = 16 * nexthops.size();
	for (std::vector<inet6_addr>::const_iterator i = nexthops.begin();
			i != nexthops.end(); ++i) {
		b.put<in6_addr>() = i->address();
	}

	b.put<uint8_t>() = 0;

	for (std::vector<inet6_addr>::const_iterator i = prefixes.begin();
						i != prefixes.end(); ++i) {
		uint8_t len = (i->prefixlen / 8);
		if (i->prefixlen & 0x7)
			len++;

		b.put<uint8_t>() = i->prefixlen;
		memcpy(b.put(len), &i->addr, len);
		nlri_len += len + 1;
	}

	return true;
}

bgp_notification_message::bgp_notification_message()
	: bgp_message(3), errorcode(0), suberrorcode(0) {}

bgp_notification_message::bgp_notification_message(const bgp_message &msg)
	: bgp_message(msg) {
}

uint16_t bgp_notification_message::length() const {
	return bgp_message::length() + 2;
}

bool bgp_notification_message::decode(encoding_buffer &b) {
	errorcode = b.eat<uint8_t>();
	suberrorcode = b.eat<uint8_t>();
	return true;
}

bool bgp_notification_message::encode(encoding_buffer &b) const {
	if (!bgp_message::encode(b))
		return false;
	b.put<uint8_t>() = errorcode;
	b.put<uint8_t>() = suberrorcode;
	return true;
}


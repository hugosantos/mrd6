/*
 * Multicast Routing Daemon (MRD)
 *   icmp.cpp
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

#include <mrd/mrd.h>
#include <mrd/icmp.h>
#include <mrd/rib.h>

bool icmp_base::register_handler(int type, icmp_handler *h) {
	handlers::iterator i = m_handlers.find(type);

	if (!h) {
		if (i != m_handlers.end())
			m_handlers.erase(i);
		else
			return false;
	} else {
		if (i != m_handlers.end())
			return false;

		m_handlers[type] = h;
	}

	registration_changed();

	return true;
}

void icmp_base::registration_changed() {
}

bool icmp_base::send_icmp(const in6_addr &dst, icmp6_hdr *hdr, uint16_t len) const {
	interface *intf = g_mrd->rib().path_towards(dst);

	if (!intf)
		return false;

	return send_icmp(intf, dst, hdr, len);
}

bool icmp_base::send_icmp(const interface *intf, const in6_addr &dst,
			  icmp6_hdr *hdr, uint16_t len) const {
	return send_icmp(intf, dst, -1, hdr, len);
}

bool icmp_base::send_icmp(const interface *intf, const in6_addr &dst,
			  int rta, icmp6_hdr *hdr, uint16_t len) const {
	if (IN6_IS_ADDR_LINKLOCAL(&dst) || IN6_IS_ADDR_MC_LINKLOCAL(&dst))
		return send_icmp(intf, *intf->linklocal(), dst, rta, hdr, len);
	else {
		if (intf->globals().empty()) {
			if (g_mrd->should_log(DEBUG)) {
				g_mrd->log().xprintf(
					"[ICMPv6] Failed to send message to "
					"%{addr}, no global address.\n", dst);
			}
			return false;
		}

		return send_icmp(intf, *intf->globals().begin(), dst, rta, hdr, len);
	}
}

bool icmp_base::send_icmp(const interface *intf, const in6_addr &src,
			  const in6_addr &to, icmp6_hdr *hdr,
			  uint16_t len) const {
	return send_icmp(intf, src, to, -1, hdr, len);
}

void icmp_base::icmp_message_available(interface *intf, const in6_addr &src,
				       const in6_addr &dst, icmp6_hdr *hdr,
				       int len) {
	handlers::iterator i = m_handlers.find((int)hdr->icmp6_type);
	if (i != m_handlers.end()) {
		i->second->icmp_message_available(intf, src, dst, hdr, len);
	} else {
		if (g_mrd->should_log(MESSAGE_CONTENT)) {
			g_mrd->log().xprintf("[ICMPv6] No handler for type "
					     "%i.\n", (int)hdr->icmp6_type);
		}
	}
}

void icmp_base::require_mgroup(const in6_addr &mgroup, bool include) {
	mgroups::iterator i = m_mgroups.find(mgroup);

	if (include) {
		if (i == m_mgroups.end()) {
			m_mgroups[mgroup] = 1;
			internal_require_mgroup(mgroup, true);
		} else {
			i->second ++;
		}
	} else {
		if (i != m_mgroups.end()) {
			i->second --;
			if (i->second == 0) {
				m_mgroups.erase(i);
				internal_require_mgroup(mgroup, false);
			}
		}
	}
}


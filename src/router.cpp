/*
 * Multicast Routing Daemon (MRD)
 *   router.cpp
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

#include <mrd/router.h>
#include <mrd/interface.h>
#include <mrd/mrd.h>
#include <mrd/mfa.h>

router::router(const char *name)
	: node(0, name) {}

router::~router() {
}

void router::attach(mrd *m) {
	m_parent = m;
}

bool router::check_startup() {
	if (!node::check_startup())
		return false;

	return true;
}

void router::shutdown() {
}

base_stream &router::log() const {
	return log_router_desc(node::log());
}

base_stream &router::log_router_desc(base_stream &os) const {
	return os;
}

interface *router::get_interface_by_index(int index) const {
	interface *intf = g_mrd->get_interface_by_index(index);
	if (intf->conf()->is_router_enabled(name()))
		return intf;
	return 0;
}

void router::created_group(group *) {
	/* empty */
}

void router::released_group(group *) {
	/* empty */
}

void router::add_interface(interface *) {
	/* empty */
}

void router::remove_interface(interface *) {
	/* empty */
}

intfconf_node *router::create_interface_configuration(intfconf *) {
	return 0;
}

groupconf_node *router::create_group_configuration(groupconf *) {
	return 0;
}

void router::mfa_notify(mfa_group_source *, const in6_addr &, const in6_addr &,
			uint32_t flags, mfa_group_source::action, interface *iif,
			ip6_hdr *, uint16_t alen, uint16_t len) {
}

void router::event(int id, void *param) {
	switch (id) {
	case mrd::InterfaceStateChanged:
		{
			interface *intf = (interface *)param;

			if (intf->up()) {
				if (intf->conf()->is_router_enabled(name()))
					add_interface(intf);
			} else {
				remove_interface(intf);
			}
		}
		break;
	case mrd::NewGroup:
		created_group((group *)param);
		break;
	case mrd::ReleasedGroup:
		released_group((group *)param);
		break;
	default:
		node::event(id, param);
	}
}


/*
 * Multicast Routing Daemon (MRD)
 *   dummy.cpp
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

#include <mrdpriv/dummy/mfa.h>
#include <mrdpriv/dummy/rib.h>

dummy_mfa_group_source::dummy_mfa_group_source(dummy_mfa_group *, const in6_addr &, uint32_t, action *) {}

void dummy_mfa_group_source::change_flags(uint32_t, action) {}

void dummy_mfa_group_source::set_iif(interface *) {}
void dummy_mfa_group_source::release_iif(interface *) {}

void dummy_mfa_group_source::add_oif(interface *) {}
void dummy_mfa_group_source::release_oif(interface *) {}

void dummy_mfa_group_source::forward(ip6_hdr *, uint16_t) const {}

dummy_mfa_group::dummy_mfa_group(dummy_mfa_instance *, const inet6_addr &) {}

void dummy_mfa_group::activate(bool) {}

mfa_group_source *dummy_mfa_group::create_source_state(const in6_addr &addr, void *) {
	return new dummy_mfa_group_source(this, addr, 0, 0);
}

void dummy_mfa_group::release_source_state(mfa_group_source *src) {
	delete src;
}

void dummy_mfa_group::change_default_flags(uint32_t, mfa_group_source::action) {}

dummy_mfa_instance::dummy_mfa_instance(dummy_mfa *, router *) {}

mfa_group *dummy_mfa_instance::create_group(const inet6_addr &addr, void *) {
	return new dummy_mfa_group(this, addr);
}

void dummy_mfa_instance::release_group(mfa_group *grp) {
	delete grp;
}

void dummy_mfa_instance::change_group_default_flags(uint32_t, mfa_group_source::action) {}

dummy_mfa::dummy_mfa() {}

bool dummy_mfa::check_startup() {
	return node::check_startup();
}

void dummy_mfa::shutdown() {}

mfa_instance *dummy_mfa::alloc_instance(router *r) {
	return new dummy_mfa_instance(this, r);
}

void dummy_mfa::added_interface(interface *intf) {}
void dummy_mfa::removed_interface(interface *intf) {}

dummy_rib::dummy_rib() {}

bool dummy_rib::check_startup() {
	return true;
}
void dummy_rib::shutdown() {}

void dummy_rib::register_route(rib_watcher_base *, const inet6_addr &) {}
void dummy_rib::unregister_route(rib_watcher_base *) {}
void dummy_rib::update_route(rib_watcher_base *) {}

interface *dummy_rib::path_towards(const inet6_addr &, inet6_addr &, inet6_addr &, inet6_addr &) const {
	return 0;
}


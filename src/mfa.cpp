/*
 * Multicast Routing Daemon (MRD)
 *   mfa.cpp
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

#include <mrd/mfa.h>
#include <mrd/mrd.h>

mfa_group_source::mfa_group_source() {
}

mfa_group_source::~mfa_group_source() {
}

mfa_group::mfa_group(router *owner)
	: m_owner(owner) {
}

mfa_core::mfa_core()
	: node(g_mrd, "mfa") {

      change_group_default_flags(mfa_group_source::f_wrong_iif,
				 mfa_group_source::copy_metadata);

}

bool mfa_core::pre_startup() {
	if (!node::check_startup())
		return false;

	g_mrd->add_child(this);

	return true;
}

mfa_core *mfa_core::mfa() {
	return g_mrd->m_mfa;
}


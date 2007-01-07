/*
 * Multicast Routing Daemon (MRD)
 *   dummy/mfa.h
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

#ifndef _mrd_dummy_mfa_h_
#define _mrd_dummy_mfa_h_

#include <mrd/mrd.h>
#include <mrd/mfa.h>
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/timers.h>

#include <stdint.h>

#include <list>
#include <map>

class interface;
class router;

struct ip6_hdr;

class dummy_mfa_group_source;
class dummy_mfa_group;
class dummy_mfa_instance;
class dummy_mfa;

class dummy_mfa_group_source : public mfa_group_source {
public:
	dummy_mfa_group_source(dummy_mfa_group *, const in6_addr &, uint32_t, action *);

	void change_flags(uint32_t, action);

	void set_iif(interface *);
	void release_iif(interface *);

	void add_oif(interface *);
	void release_oif(interface *);

	void forward(ip6_hdr *, uint16_t) const;
};

class dummy_mfa_group : public mfa_group {
public:
	dummy_mfa_group(dummy_mfa_instance *, const inet6_addr &);

	void activate(bool);

	mfa_group_source *create_source_state(const in6_addr &, void *);
	void release_source_state(mfa_group_source *);

	void change_default_flags(uint32_t, mfa_group_source::action);
};

class dummy_mfa_instance : public mfa_instance {
public:
	dummy_mfa_instance(dummy_mfa *, router *);

	mfa_group *create_group(const inet6_addr &, void *);
	void release_group(mfa_group *);

	void change_group_default_flags(uint32_t, mfa_group_source::action);
};

class dummy_mfa : public mfa_core {
public:
	dummy_mfa();

	bool check_startup();
	void shutdown();

	mfa_instance *alloc_instance(router *);

	void added_interface(interface *);
	void removed_interface(interface *);
};

#endif


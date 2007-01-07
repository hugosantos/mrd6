/*
 * Multicast Routing Daemon (MRD)
 *   mfa.h
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

#ifndef _mrd_mfa_h_
#define _mrd_mfa_h_

#include <stdint.h>

#include <mrd/address.h>
#include <mrd/node.h>

class router;
class interface;

struct ip6_hdr;

class mfa_group_source {
public:
	mfa_group_source();
	virtual ~mfa_group_source();

	enum {
		any_incoming = 0,
		wrong_iif,
		event_count
	};

	enum {
		f_any_incoming = 1,
		f_wrong_iif = 2,
	};

	enum action {
		no_action = 0,
		notify_no_copy,
		copy_metadata,
		copy_full_packet
	};

	virtual void change_flags(uint32_t, action) = 0;

	virtual void set_iif(interface *) = 0;
	virtual void release_iif(interface *) = 0;

	virtual void add_oif(interface *) = 0;
	virtual void release_oif(interface *) = 0;

	virtual void get_input_counter(uint64_t &bytes) const = 0;
	virtual void get_forwarding_counter(uint64_t &bytes) const = 0;

	void *instowner;
};

class mfa_group {
public:
	mfa_group(router *owner);
	virtual ~mfa_group() {}

	router *owner() const { return m_owner; }

	virtual void activate(bool) = 0;

	virtual mfa_group_source *create_source_state(const in6_addr &, void * = 0) = 0;
	virtual void release_source_state(mfa_group_source *) = 0;

	virtual void change_default_flags(uint32_t, mfa_group_source::action) = 0;

	void *instowner;

private:
	router *m_owner;
};

/*!
 * \brief implements the core interface with the current
 * MFA (Multicast forwarding agent).
 */
class mfa_core : public node {
public:
	virtual ~mfa_core() {}

	virtual bool pre_startup();
	virtual bool check_startup() = 0;
	virtual void shutdown() = 0;

	virtual void added_interface(interface *) {}
	virtual void removed_interface(interface *) {}

	virtual mfa_group *create_group(router *, const inet6_addr &, void * = 0) = 0;
	virtual void release_group(mfa_group *) = 0;

	virtual void change_group_default_flags(uint32_t, mfa_group_source::action) {}

	virtual void forward(interface *, ip6_hdr *, uint16_t) const = 0;

	static mfa_core *mfa();

protected:
	mfa_core();
};

#endif


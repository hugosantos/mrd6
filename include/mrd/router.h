/*
 * Multicast Routing Daemon (MRD)
 *   router.h
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

#ifndef _mrd_router_h_
#define _mrd_router_h_

#include <map>
#include <string>

#include <mrd/node.h>
#include <mrd/mfa.h>
#include <mrd/group.h>

class mrd;
class group;
class router;
class interface;

class intfconf;
class intfconf_node;
class groupconf;
class groupconf_node;

class mfa_group;

/*!
 * Each routing protocol (PIM, etc) in `mrd' derives from this
 * router class which provides an interface with the core router
 * for event notification, mfa interaction, etc. This class also
 * follows the configuration protocol through the `node' class.
 */
class router : public node, public source_discovery_sink  {
public:
	router(const char *);
	virtual ~router();

	virtual void attach(mrd *);
	virtual bool check_startup();
	virtual void shutdown();

	/* logging */
	base_stream &log() const;
	virtual base_stream &log_router_desc(base_stream &) const;

	/*!
	 * router implementations should use this method instead of
	 * mrd::get_interface_by_index in order to comply with configured
	 * parameters, including the disabling of this router instance
	 */
	interface *get_interface_by_index(int) const;

	/*!
	 * Event triggered whenever a new group instance is created.
	 * router implementations should attach their own group_node
	 * instances at this point if they wish to react to group
	 * filter changes
	 */
	virtual void created_group(group *);
	virtual void released_group(group *);

	/*!
	 * This method is called whenever a new interface is added to
	 * the system. If for some reason the router instance wishes
	 * to prevent the interface's inclusion, it should return false,
	 * effectively vetoing the new interface
	 */
	virtual void add_interface(interface *);
	virtual void remove_interface(interface *);

	virtual intfconf_node *create_interface_configuration(intfconf *);
	virtual groupconf_node *create_group_configuration(groupconf *);

	virtual void mfa_notify(mfa_group_source *, const in6_addr &, const in6_addr &,
				uint32_t flags, mfa_group_source::action, interface *iif,
				ip6_hdr *, uint16_t alen, uint16_t len);

	void event(int, void *);
};

#endif


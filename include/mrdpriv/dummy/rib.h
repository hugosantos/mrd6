/*
 * Multicast Routing Daemon (MRD)
 *  dummy/rib.h 
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

#ifndef _mrd_dummy_rib_h_
#define _mrd_dummy_rib_h_

#include <mrd/mrd.h>
#include <mrd/rib.h>
#include <mrd/timers.h>

#include <map>
#include <list>

class dummy_rib : public rib_def {
public:
	dummy_rib();

	bool check_startup();
	void shutdown();

	void register_route(rib_watcher_base *, const inet6_addr &);
	void unregister_route(rib_watcher_base *);
	void update_route(rib_watcher_base *);

	interface *path_towards(const inet6_addr &, inet6_addr &, inet6_addr &, inet6_addr &) const;
};

#endif


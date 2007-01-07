/*
 * Multicast Routing Daemon (MRD)
 *   pim_module.cpp
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

#include <mrdpriv/pim/router.h>
#include <mrdpriv/pim/interface.h>
#include <mrdpriv/pim/group.h>
#include <mrdpriv/pim/neighbour.h>
#include <mrdpriv/pim/def.h>

#include <mrd/mrd.h>
#include <mrd/rib.h>

extern pim_router *pim;

class pim_module : public mrd_module {
public:
	pim_module(mrd *, void *dlh);

	bool check_startup();
	void shutdown();
};

module_entry(pim, pim_module);

pim_module::pim_module(mrd *m, void *dlh) : mrd_module(m, dlh) {
}

bool pim_module::check_startup() {
	pim = new pim_router();
	if (!pim)
		return false;
	if (!g_mrd->register_router(pim)) {
		delete pim;
		pim = 0;
		return false;
	}
	return true;
}

void pim_module::shutdown() {
	g_mrd->unregister_router(pim);

	pim->shutdown();
	delete pim;
	pim = 0;
}


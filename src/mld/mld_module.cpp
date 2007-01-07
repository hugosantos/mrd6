/*
 * Multicast Routing Daemon (MRD)
 *   mld_module.cpp
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

#include <mrdpriv/mld/router.h>
#include <mrdpriv/mld/def.h>

#include <mrd/mrd.h>
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/group.h>

extern mld_router *mld;

class mld_module : public mrd_module {
public:
	mld_module(mrd *m, void *dlh);

	bool check_startup();
	void shutdown();

	void module_loaded(const char *, mrd_module *);
};

module_entry(mld, mld_module);

mld_module::mld_module(mrd *m, void *dlh) : mrd_module(m, dlh) {
}

bool mld_module::check_startup() {
	mld = new mld_router();
	if (!mld)
		return false;
	if (!g_mrd->register_router(mld)) {
		delete mld;
		mld = 0;
		return false;
	}
	return true;
}

void mld_module::shutdown() {
	g_mrd->unregister_router(mld);
	mld->shutdown();
	delete mld;
	mld = 0;
}

void mld_module::module_loaded(const char *name, mrd_module *) {
}


/*
 * Multicast Routing Daemon (MRD)
 *   modules.cpp
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

extern "C" mrd_module *mrd_module_init_mld(void *, mrd *);
extern "C" mrd_module *mrd_module_init_pim(void *, mrd *);
extern "C" mrd_module *mrd_module_init_bgp(void *, mrd *);
extern "C" mrd_module *mrd_module_init_console(void *, mrd *);

void mrd::add_static_modules() {
#ifdef MRD_STATIC_MLD
	m_static_modules["mld"] = &mrd_module_init_mld;
#endif

#ifdef MRD_STATIC_PIM
	m_static_modules["pim"] = &mrd_module_init_pim;
#endif

#ifdef MRD_STATIC_BGP
	m_static_modules["bgp"] = &mrd_module_init_bgp;
#endif

#ifdef MRD_STATIC_CONSOLE
	m_static_modules["console"] = &mrd_module_init_console;
#endif
}


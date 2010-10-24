/*
 * Multicast Routing Daemon (MRD)
 *   mrd_components.cpp
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

#include <mrdpriv/ks_mfa.h>
#include <mrdpriv/bsd/rib.h>

bool mrd::prepare_os_components() {
	m_mfa = new ks_mfa();

	return true;
}

void mrd::prepare_second_components() {
	if (!m_rib_handler)
		m_rib_handler = new bsd_rib();
}

const char *mrd::loopback_interface_name() const {
	return "lo0";
}

void mrd::output_backtrace(base_stream &out) const {
	out.writeline("Backtraces aren't available in this system.");
}

char *mrd::obtain_frame_description(void *ptr) const {
	return 0;
}

void *mrd::posix_uctx::get_current_frame() const {
	return 0;
}


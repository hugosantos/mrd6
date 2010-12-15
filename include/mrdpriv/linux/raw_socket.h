/*
 * Multicast Routing Daemon (MRD)
 *   mrdpriv/linux/raw_socket.h
 *
 * Copyright (C) 2010 - CSC - IT Center for Science Ltd.
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
 * Author:  Teemu Kiviniemi <firstname.lastname@iki.fi>
 */

#ifndef _mrd_linux_raw_socket_h_
#define _mrd_linux_raw_socket_h_

#include <mrd/mrd.h>

template<class Holder>
class linux_raw_socket : public socket_base {
public:
	linux_raw_socket(const char *name, Holder *holder);

	void callback(uint32_t);

#ifndef LINUX_NO_MMAP
	void *m_mmapped;
	uint32_t m_framesize;
	uint32_t m_mmappedlen;
	uint8_t *m_mmapbuf;
#endif
 private:
	Holder *m_holder;
};

template<class Holder>
linux_raw_socket<Holder>::linux_raw_socket(const char *name, Holder *holder)
	: socket_base(name),
#ifndef LINUX_NO_MMAP
		    m_mmapped(NULL),
		    m_framesize(2048),
		    m_mmappedlen(1024*1024),
		    m_mmapbuf(NULL),
#endif
		    m_holder(holder) {
}

template<class Holder>
void linux_raw_socket<Holder>::callback(uint32_t) {
	m_holder->data_available(this);
}


#endif

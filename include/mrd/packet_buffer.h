/*
 * Multicast Routing Daemon (MRD)
 *   packet_buffer.h
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

#ifndef _mrd_packet_buffer_h_
#define _mrd_packet_buffer_h_

#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

struct ip6_hdr;

class interface;
class socket_base;

/*!
 * \class std_packet_buffer mrd/packet_buffer.h
 * \brief Implements a packet buffer with pre-reserve head-space for
 * fast encapsulation.
 */
template <int BS, int EBS>
class std_packet_buffer {
public:
	std_packet_buffer()
		: source(0), rlength(-1), read_offset(0), send_offset(0) {
		memset(pb_buf, 0, sizeof(pb_buf));
	}

	template <class T> T *header(int offset = 0) { return (T *)(pb_buf + EBS + offset); }
	void *pheader(int offset = 0) { return pb_buf + EBS + offset; }

	ip6_hdr *ip6_header() { return (ip6_hdr *)(pb_buf + EBS + read_offset); }

	int recvfrom(int sock, sockaddr *sa, socklen_t *salen) {
		rlength = ::recvfrom(sock, pb_buf + EBS, BS - EBS, 0, sa, salen);
		read_offset = 0;
		return rlength;
	}

	int sendto(int sock, const sockaddr *sa, socklen_t salen) {
		int res = ::sendto(sock, pb_buf + EBS + send_offset, rlength, 0, sa, salen);
		send_offset = 0;
		return res;
	}

	void full_resize(int length) {
		rlength = length;
	}

	void set_send_offset(int length) {
		send_offset -= length;
		rlength += length;
	}

	uint8_t *buffer() { return pb_buf + EBS; }
	const uint8_t *buffer() const { return pb_buf + EBS; }

	uint32_t bufferlen() const { return BS - EBS; }

	interface *source;

	int rlength;

	int read_offset, send_offset;

	int auxhdr_off, auxhdr_len;

private:
	uint8_t pb_buf[BS];
};

typedef std_packet_buffer<4096, 256> packet_buffer;

class encoding_buffer {
public:
	encoding_buffer(int);
	~encoding_buffer();

	bool check_startup();

	bool require(int len) const { return (m_head + len) <= m_tail; }
	bool tail_require(int len) const { return (m_tail + len) <= m_end; }

	void *eat(int);
	void *put(int);

	uint8_t *head() const { return m_head; }
	uint8_t *tail() const { return m_tail; }

	uint32_t data_length() const { return m_tail - m_head; }
	uint32_t available_length() const { return m_end - m_tail; }

	void advance_head(int);
	void advance_tail(int);
	void compact();
	void clear();

	bool empty() const { return m_head == m_tail; }

	/* Helpers */
	template <class T> T &eat() { return *((T *)eat(sizeof(T))); }
	template <class T> T &put() { return *((T *)put(sizeof(T))); }

	int neatl() { return ntohl(eat<int>()); }
	uint32_t neatu32() { return ntohl(eat<uint32_t>()); }
	uint8_t neatu8() { return eat<uint8_t>(); }
	uint16_t neatu16() { return ntohs(eat<uint16_t>()); }

	int consume(socket_base &, bool blocking = false);
	int flush_to(socket_base &, bool wantsread, bool blocking = false);

private:
	uint8_t *m_buffer, *m_end;
	uint8_t *m_head, *m_tail;
};

#endif


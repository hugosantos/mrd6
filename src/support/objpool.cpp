/*
 * Multicast Routing Daemon (MRD)
 *   objpool.cpp
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

#include <mrd/support/objpool.h>
#include <mrd/support/lists.h>
#include <assert.h>

#ifndef SUPPORT_NO_POOLING

base_objpool::base_objpool(uint32_t _count, uint32_t _single)
	: granularity(_count), single(_single), light(0), heavy(0) {
	assert(granularity > 0);
}

base_objpool::base_objpool(const base_objpool &pool)
	: granularity(pool.granularity), single(pool.single), light(0), heavy(0) {
}

void *base_objpool::generic_request_obj() {
	if (!light) {
		/* There are no mem chunks with free objects */
		light = _alloc_chunk(granularity);
		if (!light)
			return 0;
	}

	/* assert(head->head) */

	_objhead *h = light->head;
	light->head = h->next;

	/* Every node with next=0 is allocated */
	h->next = 0;

	light->free --;

	if (light->free == 0) {
		/* move this light mem chunk to heavy mem chunks */
		_memchunk *m = dlist_pop_front(light);
		dlist_push_front(heavy, m);
	}

	return &h->_obj;
}

void base_objpool::base_return_obj(void *obj, _memchunk * &m) {
	_objhead *h = (_objhead *)(((uint8_t *)obj) - sizeof(_objhead));

	assert(h->next == 0);
	assert(h->parent);

	m = _find_chunk(h);

	/* assert(m = _find_chunk(h, prev)); */

	h->next = m->head;
	m->head = h;

	m->free ++;

	if (m->free == 1) {
		/* mem chunk is light again */
		dlist_remove(heavy, m);
		dlist_push_front(light, m);
	}
}

base_objpool::_memchunk *base_objpool::_alloc_chunk(uint32_t count) {
	uint32_t one_size = sizeof(_objhead) + single;
	uint32_t size = sizeof(_memchunk) + count * one_size;

	uint8_t *mb = new uint8_t[size];
	_memchunk *m = (_memchunk *)mb;

	if (m) {
		m->chunk = mb + sizeof(_memchunk);
		m->endchunk = mb + size;
		m->prev = m->next = 0;
		m->head = (_objhead *)m->chunk;
		m->count = count;
		m->free = count;

		uint8_t *p = m->chunk;
		while (p < m->endchunk) {
			_objhead *h = (_objhead *)p;
			p += one_size;
			h->parent = m;
			h->next = (_objhead *)p;
		}
	}

	return m;
}

void base_objpool::_free_chunk(_memchunk *m) {
	uint8_t *mb = (uint8_t *)m;

	delete [] mb;
}

base_objpool::_memchunk *base_objpool::_find_chunk(_objhead *h) {
	return h->parent;
}

void base_objpool::_clear_memchunks() {
	_clear_memchunks(heavy);
	_clear_memchunks(light);
}

void base_objpool::_clear_memchunks(_memchunk *m) {
	while (m) {
		_memchunk *h = m;
		m = m->next;

		_free_chunk(h);
	}
}

#endif


/*
 * Multicast Routing Daemon (MRD)
 *   objpool.h
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

#ifndef _objpool_h_
#define _objpool_h_

#include <stdint.h>
#include <assert.h>

#include <new> /* for placement new */

#ifndef SUPPORT_NO_POOLING
class base_objpool {
public:
	base_objpool(uint32_t _count, uint32_t _single);
	base_objpool(const base_objpool &pool);

	void *generic_request_obj();

protected:
	struct _memchunk;

	struct _objhead {
		/* 2 * sizeof(void *) per object */
		_memchunk *parent;
		_objhead *next;
		uint8_t _obj[0];
	} __attribute((packed));

	struct _memchunk {
		uint8_t *chunk, *endchunk;
		uint32_t count, free;
		_memchunk *prev, *next;
		_objhead *head;
	} __attribute((packed));

	void base_return_obj(void *obj, _memchunk * &m);

	_memchunk *_alloc_chunk(uint32_t count);
	void _free_chunk(_memchunk *m);
	_memchunk *_find_chunk(_objhead *h);
	void _clear_memchunks(_memchunk *);
	void _clear_memchunks();

	uint32_t granularity, single;

	_memchunk *light, *heavy;
};

template<typename objtype>
class objpool : public base_objpool {
public:
	objpool(uint32_t _count)
		: base_objpool(_count, sizeof(objtype)) {}

	objpool(const objpool<objtype> &pool)
		: base_objpool(pool) {}

	~objpool() {
		clear();
	}

	void clear() {
		clear(heavy);
		clear(light);

		_clear_memchunks();
	}

	objtype *request_obj() {
		void *p = generic_request_obj();
		if (!p)
			return 0;

		/* XXX handle exceptions in constructor */

		return new (p) objtype();
	}

	/* One of each helper method below for the number of arguments */

	template <typename Arg>
	objtype *request_obj(const Arg &arg) {
		void *p = generic_request_obj();
		if (!p)
			return 0;

		/* XXX handle exceptions in constructor */

		return new (p) objtype(arg);
	}

	template <typename Arg1, typename Arg2>
	objtype *request_obj(const Arg1 &arg1, const Arg2 &arg2) {
		void *p = generic_request_obj();
		if (!p)
			return 0;

		/* XXX handle exceptions in constructor */

		return new (p) objtype(arg1, arg2);
	}

	void return_obj(objtype *obj) {
		_memchunk *m;

		base_return_obj(obj, m);

		obj->~objtype();

		if (m->free == m->count) {
			if (!m->prev)
				light = m->next;
			else
				m->prev->next = m->next;

			_free_chunk(m);
		}
	}

private:
	void clear(_memchunk *head) {
		uint32_t one_size = sizeof(_objhead) + sizeof(objtype);

		for (; head; head = head->next) {
			for (uint8_t *p = head->chunk; p < head->endchunk;
					p += one_size) {
				_objhead *h = (_objhead *)p;

				if (h->next == 0)
					((objtype *)&h->_obj)->~objtype();
			}
		}
	}
};

#else

template<typename objtype>
class objpool {
public:
	objpool(uint32_t _count) {
	}

	objpool(const objpool<objtype> &pool) {
	}

	~objpool() {
	}

	void clear() {
		/* empty */
	}

	objtype *request_obj() {
		return new objtype();
	}

	template <typename Arg>
	objtype *request_obj(const Arg &arg) {
		return new objtype(arg);
	}

	template <typename Arg1, typename Arg2>
	objtype *request_obj(const Arg1 &arg1, const Arg2 &arg2) {
		return new objtype(arg1, arg2);
	}

	void return_obj(objtype *obj) {
		delete obj;
	}
};
#endif

#endif


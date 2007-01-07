/*
 * Multicast Routing Daemon (MRD)
 *   refcount.h
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

#ifndef _support_refcount_h_
#define _support_refcount_h_

class refcountable {
public:
	refcountable();
	virtual ~refcountable();

	void grab();
	void release();

	int get_refcount() const;

protected:
	virtual void destructor();

private:
	int _refcount;
};

class auto_grab {
public:
	auto_grab(refcountable *_t) : t(_t) {
		t->grab();
	}

	~auto_grab() {
		if (t)
			t->release();
	}

private:
	refcountable *t;
};

inline refcountable::refcountable() : _refcount(0) {}
inline refcountable::~refcountable() { /* assert(_refcount == 0); */ }

inline void refcountable::grab() {
	_refcount ++;
}

inline void refcountable::release() {
	_refcount --;
	if (_refcount == 0)
		destructor();
}

inline int refcountable::get_refcount() const {
	return _refcount;
}

inline void refcountable::destructor() {
	delete this;
}

#endif


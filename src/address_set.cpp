/*
 * Multicast Routing Daemon (MRD)
 *   address_set.cpp
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

#include <mrd/log.h>
#include <mrd/address.h>
#include <mrd/address_set.h>

address_set &address_set::union_with(const address_set &b, address_set &diff) {
	for (const_iterator i = b.begin(); i != b.end(); ++i) {
		if (insert(*i).second)
			diff.insert(*i);
	}
	return *this;
}

address_set &address_set::union_with(const address_set &b) {
	for (const_iterator i = b.begin(); i != b.end(); ++i) {
		insert(*i);
	}
	return *this;
}

address_set &address_set::diff_with(const address_set &b, address_set &diff) {
	if (!empty() && !b.empty()) {
		for (iterator i = b.begin(); i != b.end(); ++i) {
			iterator j = find(*i);
			if (j != end()) {
				diff.insert(*j);
				erase(j);
			}
		}
	}
	return *this;
}

address_set &address_set::diff_with(const address_set &b) {
	if (!empty() && !b.empty()) {
		for (iterator i = b.begin(); i != b.end(); ++i) {
			iterator j = find(*i);
			if (j != end()) {
				erase(j);
			}
		}
	}
	return *this;
}

address_set &address_set::intersect_with(const address_set &b) {
	if (b.empty()) {
		clear();
	} else {
		for (iterator i = begin(); i != end(); ++i) {
			if (!b.has_addr(*i)) {
				erase(i);
			}
		}
		for (const_iterator j = b.begin(); j != b.end(); ++j) {
			insert(*j);
		}
	}
	return *this;
}

address_set &address_set::intersect_with(const address_set &b, address_set &diff) {
	if (b.empty()) {
		diff = *this;
		clear();
	} else {
		for (iterator i = begin(); i != end(); ++i) {
			if (!b.has_addr(*i)) {
				diff.insert(*i);
				erase(i);
			}
		}
		for (const_iterator j = b.begin(); j != b.end(); ++j) {
			insert(*j);
		}
	}
	return *this;
}

address_set &address_set::assign_with(const address_set &b, address_set &added, address_set &removed) {
	if (b.empty()) {
		removed = *this;
		clear();
	} else {
		for (const_iterator i = b.begin(); i != b.end(); ++i) {
			if (!has_addr(*i))
				added.insert(*i);
		}
		for (const_iterator i = begin(); i != end(); ++i) {
			if (!b.has_addr(*i))
				removed.insert(*i);
		}
		*this = b;
	}

	return *this;
}

bool address_set::remove(const in6_addr &addr) {
	iterator i = find(addr);
	if (i == end())
		return false;
	erase(i);
	return true;
}

base_stream &address_set::print_to(base_stream &os) const {
	if (empty()) {
		os.write("{}");
	} else {
		os.write("{");

		for (address_set::const_iterator i = begin(); i != end(); ++i) {
			if (i != begin())
				os.write(", ");
			stream_push_formated_type(os, *i);
		}

		os.write("}");
	}

	return os;
}

base_stream &operator << (base_stream &os, const address_set &addrs) {
	return addrs.print_to(os);
}


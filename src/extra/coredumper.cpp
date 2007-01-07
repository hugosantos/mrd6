/*
 * Multicast Routing Daemon (MRD)
 *   coredumper.cpp
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
#include <mrd/node.h>

#include <google/coredumper.h>

static const method_info coredumper_methods[] = {
	{ "dump", 0, 1000, false, 0 },
	{ 0 }
};

class coredumper_module : public mrd_module, public node {
public:
	coredumper_module(mrd *m, void *);
	~coredumper_module();

	bool check_startup();
	void shutdown();

	bool call_method(int id, base_stream &,
			 const std::vector<std::string> &);

	bool dump(base_stream &);
};

module_entry(coredumper, coredumper_module);

coredumper_module::coredumper_module(mrd *m, void *dlh)
	: mrd_module(m, dlh), node(m, "coredumper") {}

coredumper_module::~coredumper_module() {
}

bool coredumper_module::check_startup() {
	if (!node::check_startup())
		return false;
	import_methods(coredumper_methods);
	return m_mrd->add_child("coredumper", this) != 0;
}

void coredumper_module::shutdown() {
	m_mrd->remove_child("coredumper");
}

bool coredumper_module::call_method(int id, base_stream &out,
				    const std::vector<std::string> &args) {
	if (id == 1000)
		return dump(out);
	return node::call_method(id, out, args);
}

bool coredumper_module::dump(base_stream &out) {
	char filename[256];

	sprintf(filename, "coredump-%u", (uint32_t)time(0));

	if (WriteCoreDump(filename) < 0) {
		out << "Failed to write coredump." << endl;
	} else {
		out << "Core dumped to " << filename << endl;
	}

	return true;
}


/*
 * Multicast Routing Daemon (MRD)
 *   node.cpp
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

#include <mrd/node.h>
#include <mrd/address.h>

#include <mrd/mrd.h>

#include <assert.h>
#include <cstdlib>
#include <cstdarg>

enum {
	node_method_enable	= 10,
	node_method_disable,
	node_method_no,
	node_method_show_properties
};

/* Default node methods. */
static const method_info node_methods[] = {
	{ "enable", 0, node_method_enable, false,	property_def::DEFAULT_VALUE },
	{ "disable", 0, node_method_disable, false,	property_def::DEFAULT_VALUE },
	{ "no", 0, node_method_no, false,		property_def::DEFAULT_VALUE },
	{ "properties", 0, node_method_show_properties, true,
			property_def::COMPLETE_M | property_def::DEFAULT_VALUE},
	{ 0 }
};

enum {
	statistics_node_method_reset_counters = 100,
};

static const method_info statistics_node_methods[] = {
	{ "reset-counters", 0, statistics_node_method_reset_counters, false, property_def::COMPLETE_M },
	{ 0 }
};

struct propval_bool : propval {
	propval_bool(const bool *b)
		: value(b ? *b : false) {}

	const void *get_value() const { return &value; }
	bool set_value(const char *);
	void output_value(base_stream &) const;

	bool value;
};

struct propval_unsigned : propval {
	propval_unsigned(const uint32_t *u)
		: value(u ? *u : 0) {}

	const void *get_value() const { return &value; }
	bool set_value(const char *);
	void output_value(base_stream &) const;

	uint32_t value;
};

struct propval_time_interval : propval_unsigned {
	propval_time_interval(const uint32_t *u)
		: propval_unsigned(u) {}

	bool set_value(const char *);
};

struct propval_string : propval {
	propval_string(const char *);
	~propval_string();

	const void *get_value() const { return value; }
	bool set_value(const char *);
	void output_value(base_stream &) const;

	char *value;
};

struct propval_address : propval {
	propval_address(const inet6_addr *a)
		: value(a ? *a : inet6_addr()) {}

	const void *get_value() const { return &value; }
	bool set_value(const char *);
	void output_value(base_stream &) const;

	inet6_addr value;
};

propval::~propval() {}

bool propval_bool::set_value(const char *v) {
	if (!strcmp(v, "yes") || !strcmp(v, "true") || !strcmp(v, "1"))
		value = true;
	else if (!strcmp(v, "no") || !strcmp(v, "false") || !strcmp(v, "0"))
		value = false;
	else
		return false;
	return true;
}

void propval_bool::output_value(base_stream &os) const {
	os.write(value);
}

propval_integer::propval_integer(const int32_t *i)
	: value(i ? *i : 0) {}

const void *propval_integer::get_value() const {
	return &value;
}

bool propval_integer::set_value(const char *v) {
	char *end;

	int val = strtol(v, &end, 10);

	if (*end)
		return false;

	value = val;

	return true;
}

void propval_integer::output_value(base_stream &os) const {
	os.write(value);
}

bool propval_unsigned::set_value(const char *v) {
	char *end;

	unsigned long val = strtoul(v, &end, 10);

	if (*end)
		return false;

	value = val;

	return true;
}

void propval_unsigned::output_value(base_stream &os) const {
	os.write(value);
}

bool propval_time_interval::set_value(const char *v) {
	char *end;

	unsigned long val = strtoul(v, &end, 10);

	if (!*end || !strcmp(end, "ms"))
		value = val;
	else if (!strcmp(end, "s"))
		value = val * 1000;
	else if (!strcmp(end, "m"))
		value = val * 1000 * 60;
	else if (!strcmp(end, "h"))
		value = val * 1000 * 60 * 60;
	else
		return false;

	return true;
}

propval_string::propval_string(const char *s)
	: value(s ? strdup(s) : 0) {}

propval_string::~propval_string() {
	if (value) {
		free(value);
		value = 0;
	}
}

bool propval_string::set_value(const char *v) {
	char *n = strdup(v);
	if (!n)
		return false;

	if (value)
		free(value);

	value = n;

	return true;
}

void propval_string::output_value(base_stream &os) const {
	os.write(value);
}

bool propval_address::set_value(const char *v) {
	inet6_addr addr;

	if (!addr.set(v))
		return false;

	value = addr;

	return true;
}

void propval_address::output_value(base_stream &os) const {
	os.write(value);
}

propval_enum::propval_enum(entry *ents)
	: propval_integer(0), entries(ents) {}

bool propval_enum::set_value(const char *name) {
	for (entry *i = entries; i->name; i++) {
		if (!strcmp(i->name, name)) {
			value = i->value;
			return true;
		}
	}

	return false;
}

void propval_enum::output_value(base_stream &os) const {
	for (entry *i = entries; i->name; i++) {
		if (value == i->value) {
			os.write(i->name);
			return;
		}
	}
}

event_sink::~event_sink() {
}

void event_sink::event(int type, void *) {
	/* empty */
}

node::node(node *parent, const char *name)
	: m_parent(parent), m_name(name) {
}

node::~node() {}

bool node::check_startup() {
	import_methods(node_methods);

	return true;
}

std::string node::full_name() const {
	if (m_parent && m_parent != g_mrd) {
		std::string n = m_parent->full_name();
		n += ".";
		n += m_name;
		return n;
	} else {
		return name();
	}
}

node *node::next_similiar_node() const {
	return 0;
}

property_def *node::instantiate_property(const char *name,
					 property_def::valtype type,
					 const char *desc,
					 uint32_t flags) {
	return instantiate_property(name, type, 0, desc, flags);
}

property_def *node::instantiate_property_b(const char *name, bool def,
					   const char *desc,
					   uint32_t flags) {
	return instantiate_property(name, property_def::VAL_BOOL,
				    &def, desc, flags);
}

property_def *node::instantiate_property_i(const char *name, int32_t def,
					   const char *desc,
					   uint32_t flags) {
	return instantiate_property(name, property_def::VAL_INTEGER,
				    &def, desc, flags);
}

property_def *node::instantiate_property_u(const char *name, uint32_t def,
					   const char *desc,
					   uint32_t flags) {
	return instantiate_property(name, property_def::VAL_UNSIGNED,
				    &def, desc, flags);
}

property_def *node::instantiate_property_t(const char *name, uint32_t def,
					   const char *desc,
					   uint32_t flags) {
	return instantiate_property(name, property_def::VAL_TIME_INTERVAL,
				    &def, desc, flags);
}

property_def *node::instantiate_property_s(const char *name, const char *def,
					   const char *desc,
					   uint32_t flags) {
	return instantiate_property(name, property_def::VAL_STRING,
				    def, desc, flags);
}

property_def *node::instantiate_property_a(const char *name,
					   const inet6_addr &addr,
					   const char *desc,
					   uint32_t flags) {
	return instantiate_property(name, property_def::VAL_ADDRESS,
				    &addr, desc, flags);
}

property_def *node::instantiate_property(const char *name,
					 property_def::valtype type,
					 const void *def, const char *desc,
					 uint32_t flags) {
	if (m_properties.find(name) != m_properties.end())
		return 0;

	property_def &p = m_properties[name];

	if (!p.instantiate(type, def, desc, flags)) {
		m_properties.erase(m_properties.find(name));
		return 0;
	}

	return &p;
}

property_def *node::instantiate_property(const char *name, propval *prop,
					 const char *desc, uint32_t flags) {
	if (!prop)
		return 0;

	if (m_properties.find(name) != m_properties.end())
		return 0;

	property_def &p = m_properties[name];

	if (!p.instantiate(prop, desc, flags)) {
		delete prop;

		m_properties.erase(m_properties.find(name));
		return 0;
	}

	return &p;
}

bool node::has_property(const char *key) const {
	properties::const_iterator i = m_properties.find(key);

	return i != m_properties.end() && i->second.is_property();
}

bool node::has_child_property(const char *key) const {
	properties::const_iterator i = m_properties.find(key);

	return i != m_properties.end();
}

property_def *node::get_property(const char *n, bool strict) {
	properties::iterator i = m_properties.find(n);
	if (i == m_properties.end()) {
		if (!strict) {
			node *next = next_similiar_node();

			assert(next != this);

			if (next)
				return next->get_property(n, false);
		}
		return 0;
	}

	return i->second.is_property() ? &i->second : 0;
}

const property_def *node::get_property(const char *n, bool strict) const {
	properties::const_iterator i = m_properties.find(n);
	if (i == m_properties.end()) {
		if (!strict) {
			node *next = next_similiar_node();
			if (next)
				return next->get_property(n, false);
		}
		return 0;
	}

	return i->second.is_property() ? &i->second : 0;
}

const property_def *node::get_any_property(const char *name) const {
	properties::const_iterator i = m_properties.find(name);
	if (i == m_properties.end())
		return 0;
	return &i->second;
}

bool node::get_property_bool(const char *key) const
	{ return get_property(key)->get_bool(); }
int32_t node::get_property_integer(const char *key) const
	{ return get_property(key)->get_integer(); }
uint32_t node::get_property_unsigned(const char *key) const
	{ return get_property(key)->get_unsigned(); }
const char *node::get_property_string(const char *key) const
	{ return get_property(key)->get_string(); }
const inet6_addr &node::get_property_address(const char *key) const
	{ return get_property(key)->get_address(); }

const property_def *node::get_child_property(const char *childname,
					const char *name, bool strict) const {
	node *child = get_child(childname);

	if (child)
		return child->get_property(name, strict);

	return 0;
}

bool node::set_property(const char *name, const char *value) {
	properties::iterator i = m_properties.find(name);
	if (i == m_properties.end() || !i->second.is_property())
		return false;

	if (i->second.set_value(value)) {
		propagate_property_changed(this, name);

		return true;
	}

	return false;
}

void node::propagate_property_changed(node *n, const char *name) {
	property_changed(n, name);
}

bool node::remove_property(const char *key, bool force) {
	properties::iterator k = m_properties.find(key);
	if (k == m_properties.end() || !k->second.is_property()
		|| (!force && (k->second.is_readonly() || !k->second.is_removable())))
		return false;
	m_properties.erase(k);
	return true;
}

bool node::set_property_inst(const char *key, property_def::valtype vt,
			     const char *value) {
	properties::iterator k = m_properties.find(key);

	if (k == m_properties.end()) {
		property_def *prop =
			instantiate_property(key, vt, 0,
					     property_def::REMOVABLE);
		if (!prop)
			return false;
		if (!prop->set_value(value)) {
			remove_property(key);
			return false;
		} else {
			propagate_property_changed(this, key);
		}

		return true;
	}

	if (!k->second.is_property() || k->second.is_readonly())
		return false;

	if (k->second.set_value(value)) {
		propagate_property_changed(this, key);
		return true;
	}

	return false;
}

bool node::increment_property(const char *, const char *) {
	return false;
}

node *node::get_child(const char *name) const {
	properties::const_iterator i = m_properties.find(name);

	if (i == m_properties.end() || !i->second.is_child())
		return 0;

	return i->second.get_node();
}

node *node::get_or_create_child(const char *name) {
	node *child = get_child(name);
	if (child)
		return child;

	return create_child(name);
}

node *node::create_child(const char *) {
	return 0;
}

node *node::add_child(node *child, bool cm, const char *name, const char *desc) {
	if (!name)
		name = child->name();

	if (!name)
		return 0;

	if (m_properties.find(name) != m_properties.end())
		return 0;

	property_def &p = m_properties[name];

	if (!p.instantiate(child, cm ? property_def::COMPLETE_M : 0)) {
		m_properties.erase(m_properties.find(name));
		return 0;
	}

	if (!desc)
		desc = child->description();

	p.set_description(desc);

	return child;
}

void node::remove_child(const char *name) {
	properties::iterator i = m_properties.find(name);

	if (i == m_properties.end() || !i->second.is_child())
		return;

	node *n = i->second.get_node();

	m_properties.erase(i);

	remove_child_node(n);
}

void node::remove_child_node(node *n) {
	/* empty */
}

void node::clear_childs() {
	properties::iterator i = m_properties.begin();

	while (i != m_properties.end()) {
		properties::iterator j = i;
		++i;

		if (j->second.is_child()) {
			remove_child(j->first.c_str());
		}
	}
}

bool node::has_method(const char *name, uint32_t type) const {
	properties::const_iterator i = m_properties.find(name);

	if (i != m_properties.end() && i->second.is_method()) {
		return type == method || ((type == info_method) && i->second.is_readonly());
	}

	return false;
}

bool node::call_method(int id, base_stream &out,
		       const std::vector<std::string> &args) {
	switch (id) {
	case node_method_enable:
	case node_method_disable:
		return enable_several(args, id == node_method_enable);
	case node_method_no:
		return exec_negate(out, args);
	case node_method_show_properties:
		{
			std::string fname = m_parent ? full_name() : std::string();
			for (properties::const_iterator i = m_properties.begin();
					i != m_properties.end(); ++i) {
				if (!fname.empty())
					out.write(fname.c_str()).write(".");
				out.write(i->first.c_str()).write(" = ");
				if (i->second.is_property()) {
					i->second.output_value(out);
					if (i->second.is_readonly())
						out.write(" [readonly]");
				} else if (i->second.is_child()) {
					out.xprintf("<node %s>", i->second.get_node()->name());
				} else if (i->second.is_method()) {
					if (i->second.is_readonly())
						out.write("<info-method ");
					else
						out.write("<method ");
					out.xprintf("%s>", i->second.get_method_info()->name);
				}

				out.newl();
			}

			return true;
		}
	}

	return false;
}

bool node::negate_method(int id, base_stream &out,
			 const std::vector<std::string> &args) {
	return false;
}

void node::import_methods(const method_info *info) {
	for (int k = 0; info[k].name; k++) {
		add_method(&info[k]);
	}
}

bool node::add_method(const method_info *info) {
	if (!info || !info->name)
		return false;

	if (m_properties.find(info->name) != m_properties.end())
		return false;

	property_def &p = m_properties[info->name];

	if (!p.instantiate(info)) {
		m_properties.erase(m_properties.find(info->name));
		return false;
	}

	return true;
}

void node::remove_method(const char *name) {
	properties::iterator i = m_properties.find(name);

	if (i == m_properties.end() || !i->second.is_method())
		return;

	m_properties.erase(i);
}

bool node::output_info(base_stream &out, const std::vector<std::string> &args) const {
	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (i->second.is_child()) {
			i->second.get_node()->output_info(out, args);
		}
	}

	return true;
}

bool node::enable_several(const std::vector<std::string> &args, bool enable) {
	if (args.empty())
		return false;

	const char *ens = enable ? "true" : "false";

	node *n = this;

	int len = args.size() - 1;

	content_type ctype;
	const char *cmatch;
	int cres;

	for (int i = 0; i < len; i++) {
		cres = match_property(child, args[i].c_str(), ctype, cmatch);

		if (cres == 1) {
			n = n->get_or_create_child(cmatch);
			if (n)
				continue;
		}

		return false;
	}

	cres = n->match_property(child | property | method | info_method,
				 args[len].c_str(), ctype, cmatch);

	if (cres > 1)
		return false;

	if (cres == 0) {
		if (!n->create_child(args[len].c_str()))
			return n->set_property(args[len].c_str(), ens);

		cres = 1;
		ctype = child;
		cmatch = args[len].c_str();
	}

	if (ctype == method || ctype == info_method)
		return false;

	if (cres == 1) {
		const char *prop = cmatch;

		if (ctype == child) {
			n = n->get_child(cmatch);
			if (!n)
				return false;
			return n->set_property_inst("enabled", property_def::VAL_BOOL, ens);
		}

		if (!n->has_property(prop)) {
			node *p = n;
			while (1) {
				p = p->next_similiar_node();
				if (!p)
					return false;
				else if (p->has_property(prop)) {
					return n->set_property_inst(prop,
							property_def::VAL_BOOL,
							ens);
				}
			}
		}

		return n->set_property(prop, ens);
	}

	return false;
}

bool node::show(base_stream &out, const std::vector<std::string> &args) {
	node *final = this;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		content_type ctype;
		const char *cmatch = 0;

		int count = final->match_property(info_method | child
						  | method | property,
						  i->c_str(), ctype, cmatch);

		if (count == 0)
			return final->output_info(out,
				  std::vector<std::string>(i, args.end()));
		else if (count > 1) {
			out.writeline("% Inconsistency in input.");
			return true;
		}

		if (ctype == child) {
			final = final->get_child(cmatch);
			if (!final)
				return false;
		} else if (ctype == info_method) {
			++i;

			std::vector<std::string> newargs(i, args.end());

			properties::const_iterator j = final->m_properties.find(cmatch);
			if (j == m_properties.end())
				return false;

			int id = j->second.get_method_info()->id;

			return final->call_method(id, out, newargs);
		} else {
			out.writeline("% No such command.");
			return true;
		}
	}

	return final->output_info(out, std::vector<std::string>());
}

bool node::exec_negate(base_stream &out, const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	node *final = this;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		content_type ctype;
		const char *cmatch = 0;

		int count = final->match_property(info_method | child
						  | method | property,
						  i->c_str(), ctype, cmatch);

		if (count == 0) {
			out.writeline("% No such command.");
			break;
		} else if (count > 1) {
			out.writeline("% Inconsistency in input.");
			break;
		}

		if (ctype == child) {
			final = final->get_child(cmatch);
			if (!final)
				return false;
		} else if (ctype == method) {
			++i;

			std::vector<std::string> newargs(i, args.end());

			properties::const_iterator j = final->m_properties.find(cmatch);
			if (j == m_properties.end()) {
				out.writeline("% No such command.");
				break;
			}

			if (!(j->second.flags() & property_def::NEGATE)) {
				out.writeline("% No such command.");
				break;
			}

			int id = j->second.get_method_info()->id;

			return final->negate_method(id, out, newargs);
		} else if (ctype == property) {
			++i;
			if (i != args.end()) {
				out.writeline("% Too many arguments.");
				break;
			}
			if (!final->remove_property(cmatch)) {
				out.writeline("% Failed to remove property.");
				break;
			}
			propagate_property_changed(final, cmatch);
		} else {
			out.writeline("% No such command.");
			break;
		}
	}

	return true;
}

int node::match_property(uint32_t fl, const char *match,
			 content_type &ctype, const char * &cmatch) const {
	int cmatchcount = 0;

	cmatch = 0;

	size_t mlen = strlen(match);

	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		content_type curr = unknown;

		if (i->second.is_child())
			curr = child;
		else if (i->second.is_property())
			curr = property;
		else if (i->second.is_method())
			curr = i->second.is_readonly() ? info_method : method;
		else
			continue;

		if (!(fl & curr))
			continue;

		const char *tent = i->first.c_str();

		/* Partial match */
		if (strncmp(match, tent, mlen) == 0) {
			if (mlen == strlen(tent)) {
				/* complete match, return immediatly */
				ctype = curr;
				cmatch = tent;
				return 1;
			} else if (i->second.flags() & property_def::COMPLETE_M) {
				continue;
			}

			ctype = curr;
			cmatch = tent;

			if (i->second.flags() & property_def::COMPLETE_M) {
				return 1;
			} else if (cmatchcount == 0) {
				cmatchcount = 1;
			} else {
				return 2;
			}
		}
	}

	return cmatch ? cmatchcount : 0;
}

void node::broadcast_event(int id, void *param, bool all) {
	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (i->second.is_child()) {
			i->second.get_node()->event(id, param);

			if (all)
				i->second.get_node()->broadcast_event(id, param, true);
		}
	}
}

bool node::should_log(int level) const {
	if (m_parent == NULL)
		return false;
	return m_parent->should_log(level);
}

base_stream &node::log() const {
	return m_parent->log();
}

property_def::property_def()
	: m_flags(DEFAULT_VALUE), m_prop_description(0) {
	u.val = 0;
}

property_def::~property_def() {
	if (is_property()) {
		delete u.val;
		u.val = 0;
	}
}

bool property_def::instantiate(valtype type, const void *def,
			       const char *desc, uint32_t fl) {
	if (is_instantiated() || (fl & METHOD) || (fl & CHILD))
		return false;

	fl |= PROPERTY;

	switch (type) {
	case VAL_BOOL:
		u.val = new propval_bool((const bool *)def);
		break;
	case VAL_INTEGER:
		u.val = new propval_integer((const int32_t *)def);
		break;
	case VAL_UNSIGNED:
		u.val = new propval_unsigned((const uint32_t *)def);
		break;
	case VAL_TIME_INTERVAL:
		u.val = new propval_time_interval((const uint32_t *)def);
		break;
	case VAL_STRING:
		u.val = new propval_string((const char *)def);
		if (u.val && !((propval_string *)u.val)->value) {
			delete u.val;
			u.val = 0;
		}
		break;
	case VAL_ADDRESS:
		u.val = new propval_address((const inet6_addr *)def);
		break;
	default:
		return false;
	}

	if (!u.val)
		return false;

	m_flags |= fl;
	m_prop_description = desc;

	return true;
}

bool property_def::instantiate(node *n, uint32_t fl) {
	if (is_instantiated() || (fl & ~COMPLETE_M))
		return false;

	m_flags |= CHILD | fl;

	u.child = n;

	return true;
}

bool property_def::instantiate(const method_info *info) {
	if (!info || is_instantiated()
		|| (info->flags & CHILD) || (info->flags & PROPERTY))
		return false;

	m_flags = METHOD | info->flags
			 | (info->informational ? property_def::READ_ONLY : 0);

	u.method = info;

	return true;
}

bool property_def::instantiate(propval *pval, const char *desc, uint32_t fl) {
	if (is_instantiated() || (fl & METHOD) || (fl & CHILD)) {
		delete pval;
		return false;
	}

	u.val = pval;

	fl |= PROPERTY;

	m_flags |= fl;
	m_prop_description = desc;

	return true;
}

void property_def::set_description(const char *desc) {
	m_prop_description = desc;
}

const char *property_def::description() const {
	if (is_child() && get_node()->description())
		return get_node()->description();
	else if (is_method() && get_method_info()->description)
		return get_method_info()->description;
	return m_prop_description;
}

void property_def::set_readonly() {
	m_flags |= READ_ONLY;
}

bool property_def::set_value(const char *value, bool b) {
	if (!is_property())
		return false;

	if (u.val && u.val->set_value(value)) {
		if (b)
			m_flags &= ~DEFAULT_VALUE;
		return true;
	}

	return false;
}

void property_def::output_value(base_stream &os) const {
	if (!u.val)
		os.write("(null)");
	else
		u.val->output_value(os);
}

bool property_def::is_instantiated() const {
	return is_child() || is_property() || is_method();
}

conf_node::conf_node(node *parent, const char *name)
	: node(parent, name) {}

void conf_node::enable(bool v) {
	set_property_inst("enabled", property_def::VAL_BOOL, v ? "true" : "false");
}

void conf_node::propagate_property_changed(node *n, const char *name) {
	property_changed(n, name);

	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (i->second.is_child()) {
			i->second.get_node()->propagate_property_changed(n, name);
		}
	}
}

void conf_node::attach_watcher(node *n) {
	dettach_watcher(n);

	m_watchers.push_back(n);
}

void conf_node::dettach_watcher(node *n) {
	std::vector<node *>::iterator i = std::find(m_watchers.begin(), m_watchers.end(), n);
	if (i != m_watchers.end())
		m_watchers.erase(i);
}

void conf_node::property_changed(node *n, const char *name) {
	for (std::vector<node *>::const_iterator i = m_watchers.begin();
			i != m_watchers.end(); ++i) {
		(*i)->property_changed(n, name);
	}
}

statistics_node::statistics_node(node *parent, int count,
				 const char **descriptions)
	: node(parent, "stats"), m_count(count), m_descriptions(descriptions) {
	m_counters = new counter_type[count];
}

statistics_node::~statistics_node() {
	delete [] m_counters;
	m_counters = 0;
}

bool statistics_node::check_startup() {
	if (m_counters) {
		reset_counters();
	} else {
		return false;
	}

	import_methods(statistics_node_methods);

	return true;
}

bool statistics_node::setup(const char *description) {
	if (!check_startup())
		return false;
	return m_parent->add_child(this, false, 0, description) == this;
}

statistics_node::counter_type &statistics_node::counter(int index) const {
	return m_counters[index];
}

void statistics_node::reset_counters() {
	for (int i = 0; i < m_count; i++) {
		m_counters[i] = 0;
	}
}

bool statistics_node::call_method(int id, base_stream &out,
				  const std::vector<std::string> &args) {
	if (id == statistics_node_method_reset_counters) {
		if (!args.empty())
			return false;

		reset_counters();

		return true;
	}

	return node::call_method(id, out, args);
}

bool statistics_node::output_info(base_stream &out,
				  const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	for (int i = 0; i < m_count; i++) {
		out.printf("%s: %llu", m_descriptions[i], m_counters[i]).newl();
	}

	return true;
}

static const char *_default_type_descriptions[] = {
	"Received", "Sent", "Bad"
};

message_stats_node::message_stats_node(node *parent, int count,
				       const char **descriptions,
				       int typecount, const char **typedesc)
	: statistics_node(parent, count * typecount, descriptions),
	  m_msgcount(count), m_typecount(typecount),
	  m_typedescriptions(typedesc) {

	if (!typedesc) {
		assert(typecount == 3);
		m_typedescriptions = _default_type_descriptions;
	}

	/* we keep a 64 bitset to enable/disable stats, so make sure
	 * we don't access more than that */
	assert(count <= (int)(m_enablecounters.size() / m_typecount));

	m_enablecounters.set();
}

statistics_node::counter_type &message_stats_node::counter(int index,
							   int type) const {
	return statistics_node::counter(index * m_typecount + type);
}

void message_stats_node::disable_counter(int index, int type) {
	m_enablecounters.reset(index * m_typecount + type);
}

void message_stats_node::print_counter(base_stream &out, int index, int type) const {
	if (!m_enablecounters.test(index * m_typecount + type)) {
		out.printf(" %10s", "-");
	} else {
		out.printf(" %10u", (uint32_t)m_counters[index * m_typecount + type]);
	}
}

bool message_stats_node::output_info(base_stream &out,
				     const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	int i;

	/* 1 + 12 + 1 whites */
	out.printf("              ");
	for (i = 0; i < m_typecount; i++)
		out.printf(" %10s", m_typedescriptions[i]);
	out.newl();

	out.printf("              ");
	for (i = 0; i < m_typecount; i++)
		out.printf("-----------");
	out.writeline("-");

	for (i = 0; i < m_msgcount; i++) {
		out.printf(" %12s ", m_descriptions[i]);
		for (int j = 0; j < m_typecount; j++)
			print_counter(out, i, j);
		out.newl();
	}

	return true;
}


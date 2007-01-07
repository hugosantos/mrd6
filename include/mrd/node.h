/*
 * Multicast Routing Daemon (MRD)
 *   node.h
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

#ifndef _mrd_node_h_
#define _mrd_node_h_

#include <stdint.h>

#include <string>
#include <vector>
#include <map>
#include <deque>
#include <set>
#include <bitset>

#include <mrd/address.h>
#include <mrd/parser.h>

class base_stream;
class inet6_addr;

class node;

struct method_info {
	const char *name;
	const char *description;
	int id;
	bool informational;
	uint32_t flags;
};

/*!
 * Implements an abstract interface to property values
 */
struct propval {
	virtual ~propval();

	/*!
	 * Returns a pointer to the internal structure holding the value
	 */
	virtual const void *get_value() const = 0;
	/*!
	 * Parses the string representation specified in the param and sets
	 * the value if valid. If the input has a bad format, returns false.
	 */
	virtual bool set_value(const char *) = 0;
	/*!
	 * Outputs the current value into the specified base_stream
	 */
	virtual void output_value(base_stream &) const = 0;
};

/*!
 * Implements an interface to property definitions, including value
 * instantiation, flags and helper methods.
 */
class property_def {
public:
	property_def();
	~property_def();

	enum {
		READ_ONLY	= 0x01,
		REMOVABLE	= 0x02,
		DEFAULT_VALUE	= 0x04,
		PROPERTY	= 0x08,
		METHOD		= 0x10,
		CHILD		= 0x20,
		COMPLETE_M	= 0x40,
		NEGATE		= 0x80,
	};

	/*!
	 * Internal available value types
	 */
	enum valtype {
		VAL_UNKNOWN,
		VAL_BOOL,
		VAL_INTEGER,
		VAL_UNSIGNED,
		VAL_TIME_INTERVAL,
		VAL_STRING,
		VAL_ADDRESS,
	};

	/*!
	 * Instantiates a property to the specified type with the supplied
	 * default value. Also applies supplied flags.
	 */
	bool instantiate(valtype, const void *def, const char *desc,
			 uint32_t flags);
	/*!
	 * Provides instantiation of alien propvals. The moment the propval
	 * is fed into instantiation, the property_def will be it's owner
	 * and is responsible for freeing as required (including if this
	 * method fails).
	 */
	bool instantiate(propval *, const char *desc, uint32_t flags);

	/*! Instantiates a child node property */
	bool instantiate(node *, uint32_t flags);

	bool instantiate(const method_info *);

	bool is_readonly() const { return m_flags & READ_ONLY; }
	bool is_removable() const { return m_flags & REMOVABLE; }
	bool is_default() const { return m_flags & DEFAULT_VALUE; }

	bool is_property() const { return m_flags & PROPERTY; }
	bool is_method() const { return m_flags & METHOD; }
	bool is_child() const { return m_flags & CHILD; }

	uint32_t flags() const { return m_flags; }

	void set_description(const char *);
	const char *description() const;

	void set_readonly();
	void set_removable();

	/*!
	 * Feeds the supplied value into propval::set_value. If rch = true,
	 * removes flag DEFAULT_VALUE. This call will fail if is_property
	 * is not true.
	 */
	bool set_value(const char *, bool rch = true);

	/* helper methods */
	bool get_bool() const;
	int32_t get_integer() const;
	uint32_t get_unsigned() const;
	const char *get_string() const;
	const inet6_addr &get_address() const;
	node *get_node() const;
	const method_info *get_method_info() const;

	/*!
	 * Feeds into propval::output_value, or outputs (null) if
	 * not instantiated
	 */
	void output_value(base_stream &) const;

private:
	bool is_instantiated() const;

	uint32_t m_flags;

	union {
		propval *val;
		node *child;
		const method_info *method;
	} u;

	const char *m_prop_description;
};

inline bool property_def::get_bool() const {
	return *(const bool *)u.val->get_value();
}

inline int32_t property_def::get_integer() const {
	return *(const int32_t *)u.val->get_value();
}

inline uint32_t property_def::get_unsigned() const {
	return *(const uint32_t *)u.val->get_value();
}

inline const char *property_def::get_string() const {
	return (const char *)u.val->get_value();
}

inline const inet6_addr &property_def::get_address() const {
	return *(const inet6_addr *)u.val->get_value();
}

inline node *property_def::get_node() const {
	return u.child;
}

inline const method_info *property_def::get_method_info() const {
	return u.method;
}

class event_sink {
public:
	virtual ~event_sink();

	virtual void event(int, void *);
};

/*!
 * Implements base node class, core to the mrd internal hierarchy. nodes
 * come with property handling by default.
 */
class node : public event_sink {
public:
	node(node *, const char *);
	virtual ~node();

	virtual bool check_startup();

	/*!
	 * Returns this node's parent node.
	 */
	node *parent() const { return m_parent; }

	/*!
	 * Returns this node's name.
	 */
	const char *name() const { return m_name.c_str(); }

	/*!
	 * Returns a textual description of this node.
	 */
	virtual const char *description() const { return 0; }

	/*!
	 * Returns the full name of this node, with each parent separated
	 * by a dot (.) e.g. mrd.interfaces.eth0
	 */
	std::string full_name() const;

	/*!
	 * Should return a less specific node related to this node. Used for
	 * get_property when the node doesn't have the requested property.
	 */
	virtual node *next_similiar_node() const;

	enum content_type {
		unknown = 0,
		property = 1,
		child = 2,
		method = 4,
		info_method = 8
	};

	/*!
	 * Sets the property specified by key's value. Returns false if the
	 * specified value is not parsable by propval's requirement or the
	 * property doesn't exist.
	 */
	virtual bool set_property(const char *key, const char *value);
	/*!
	 * Removes a REMOVABLE property. Returns false if the property is not
	 * REMOVABLE or doesn't exist.
	 */
	virtual bool remove_property(const char *key, bool force = false);
	/*!
	 * Increments a property propval with value. Follows same rules
	 * as set_property
	 */
	virtual bool increment_property(const char *key, const char *value);
	/*!
	 * Returns a reference to the specified property. If strict=true,
	 * similiar nodes aren't used in case this node doesn't contain
	 * the specified property.
	 */
	const property_def *get_property(const char *key, bool strict = false) const;
	/*!
	 * Returns a modifiable reference to the specified property.
	 */
	property_def *get_property(const char *key, bool strict = false);

	const property_def *get_any_property(const char *name) const;

	/*!
	 * Same as constant get_property, but returns the property from the
	 * specified child. If the child doesn't exist, returns a null
	 * reference
	 */
	const property_def *get_child_property(const char *,
			const char *, bool strict = false) const;

	/*!
	 * These methods should only be called when you are sure of the
	 * property's content and existance
	 */
	bool get_property_bool(const char *) const;
	int32_t get_property_integer(const char *) const;
	uint32_t get_property_unsigned(const char *) const;
	const char *get_property_string(const char *) const;
	const inet6_addr &get_property_address(const char *) const;

	/*!
	 * Returns true if the node holds a property with the specified name
	 */
	virtual bool has_property(const char *) const;

	bool has_child_property(const char *) const;

	/*!
	 * Returns a reference to the specified child. A null reference will
	 * be returned if the child doesn't exist
	 */
	virtual node *get_child(const char *) const;
	/*!
	 * Returns a reference to an existing specified child, or if it doesn't
	 * exist calls create_child() and returns the new child
	 */
	virtual node *get_or_create_child(const char *);
	virtual node *create_child(const char *);

	node *add_child(node *chld, bool complete_m = false,
			const char *name = 0,
			const char *description = 0);
	/*!
	 * Removes a child node from the node
	 */
	void remove_child(const char *);

	void clear_childs();

	/*!
	 * Returns true if the node has the specified method
	 */
	virtual bool has_method(const char *name, uint32_t) const;

	/*!
	 * Implements the call handler
	 */
	virtual bool call_method(int id, base_stream &, const std::vector<std::string> &);

	virtual bool negate_method(int, base_stream &, const std::vector<std::string> &);

	/*!
	 * Imports a method table into this node's property list. The
	 * table must be terminated by an entry with name = NULL.
	 */
	void import_methods(const method_info *);

	/*!
	 * Adds a single new method to the node's property list. The
	 * method_info object must live while this node exists.
	 */
	bool add_method(const method_info *info);

	/*!
	 * Removes the specified method from the node's children list
	 */
	void remove_method(const char *name);

	/* Logging */
	virtual bool should_log(int) const;
	virtual base_stream &log() const;

	// Info

	virtual bool output_info(base_stream &, const std::vector<std::string> &) const;

	typedef std::map<std::string, property_def> properties;

	const properties &get_properties() const { return m_properties; }

	int match_property(uint32_t, const char *, content_type &, const char * &) const;

	void broadcast_event(int, void *, bool all = false);

protected:
	node *m_parent;

	properties m_properties;

	property_def *instantiate_property(const char *name,
					   property_def::valtype,
					   const char *desc = 0,
					   uint32_t flags = 0);
	property_def *instantiate_property(const char *name,
					   property_def::valtype, const void *,
					   const char *desc = 0,
					   uint32_t flags = 0);
	property_def *instantiate_property(const char *name, propval *,
					   const char *desc = 0,
					   uint32_t flags = 0);

	property_def *instantiate_property_b(const char *name, bool def,
					     const char *desc = 0,
					     uint32_t flags = 0);
	property_def *instantiate_property_i(const char *name, int32_t def,
					     const char *desc = 0,
					     uint32_t flags = 0);
	property_def *instantiate_property_u(const char *name, uint32_t def,
					     const char *desc = 0,
					     uint32_t flags = 0);
	property_def *instantiate_property_t(const char *name, uint32_t def,
					     const char *desc = 0,
					     uint32_t flags = 0);
	property_def *instantiate_property_s(const char *name, const char *def,
					     const char *desc = 0,
					     uint32_t flags = 0);
	property_def *instantiate_property_a(const char *name,
					     const inet6_addr &,
					     const char *desc = 0,
					     uint32_t flags = 0);

	bool set_property_inst(const char *name, property_def::valtype,
			       const char *value);

	bool enable_several(const std::vector<std::string> &, bool);
	bool show(base_stream &, const std::vector<std::string> &);
	bool exec_negate(base_stream &, const std::vector<std::string> &);

	virtual void propagate_property_changed(node *, const char *);
	virtual void property_changed(node *, const char *) {}

	virtual void remove_child_node(node *);

	friend class conf_node;

	std::string m_name;
};

class conf_node : public node {
public:
	conf_node(node *, const char *);

	void attach_watcher(node *);
	void dettach_watcher(node *);

	void enable(bool);

protected:
	void propagate_property_changed(node *, const char *);
	void property_changed(node *, const char *);

	std::vector<node *> m_watchers;
};

class statistics_node : public node {
public:
	typedef uint64_t counter_type;

	statistics_node(node *parent, int count, const char **descriptions);
	~statistics_node();

	bool check_startup();

	/* calls check_startup and adds itself to parent */
	bool setup(const char *description = 0);

	counter_type &counter(int index) const;

	void reset_counters();

	bool call_method(int id, base_stream &, const std::vector<std::string> &);
	bool output_info(base_stream &, const std::vector<std::string> &) const;

protected:
	int m_count;
	counter_type *m_counters;
	const char **m_descriptions;
};

class message_stats_node : public statistics_node {
public:
	message_stats_node(node *parent, int count, const char **descriptions,
			   int typecount = 3, const char **types = 0);

	statistics_node::counter_type &counter(int index, int type) const;
	void disable_counter(int index, int type);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

protected:
	void print_counter(base_stream &, int index, int type) const;

	int m_msgcount, m_typecount;
	const char **m_typedescriptions;
	std::bitset<64> m_enablecounters;
};

struct propval_integer : propval {
	propval_integer(const int32_t *);
	const void *get_value() const;
	bool set_value(const char *);
	void output_value(base_stream &) const;

	int32_t value;
};

struct propval_enum : propval_integer {
	struct entry {
		const char *name;
		int32_t value;
	};

	propval_enum(entry *);
	bool set_value(const char *);
	void output_value(base_stream &) const;

	entry *entries;
};

#endif


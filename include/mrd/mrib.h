/*
 * Multicast Routing Daemon (MRD)
 *   mrib.h
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

#ifndef _mrd_mrib_h_
#define _mrd_mrib_h_

#include <mrd/node.h>
#include <mrd/timers.h>
#include <mrd/interface.h>

#include <mrd/support/objpool.h>
#include <mrd/support/ptree.h>

#include <list>
#include <set>

class mrib_origin;
class mrib_watcher_base;

class mrib_connected_origin;
class mrib_static_origin;

/*!
 * Implements the Multicast Routing Information Base interface
 */
class mrib_def : public node {
public:
	mrib_def(node *);
	~mrib_def();

	bool check_startup();
	void shutdown();

	const char *description() const;

	typedef uint32_t metric_def;

	struct mrib_node;

	struct prefix {
		prefix(mrib_origin *, uint32_t distance = 1000);

		const inet6_addr &get_prefix() const { return trie_owner->prefix; }
		bool is_best_entry() const { return trie_owner->head == this; }

		bool is_valid() const { return intf && intf->up(); }

		in6_addr nexthop;
		interface *intf;
		mrib_origin *owner;
		time_t creation;

		enum {
			NO_EXPORT = 1,
		};

		uint32_t flags;

		uint32_t distance;
		metric_def metric;

		/* private */
		uint32_t refcount;
		mrib_node *trie_owner;
		struct prefix *next;
	};

	struct mrib_node : ptree_node {
		uint32_t refcount;
		inet6_addr prefix;
		struct prefix *head;
		mrib_watcher_base *watchhead;
	};

	typedef ptree<inet6_addr, mrib_node> mrib_trie;

	mrib_connected_origin &local() { return *m_local; }

	const prefix *resolve_nexthop(const inet6_addr &,
				      const inet6_addr &,
				      inet6_addr &) const;
	const prefix *prefix_lookup(const inet6_addr &,
				    const inet6_addr &) const;

	prefix *get_prefix(const inet6_addr &, mrib_origin *) const;

	bool install_prefix(const inet6_addr &, prefix *);
	void update_prefix(prefix *);
	void remove_prefix(prefix *);

	void install_listener(mrib_origin *);
	void origin_lost(mrib_origin *);

	void invalidate_watcher(mrib_watcher_base *);

	bool call_method(int id, base_stream &,
			 const std::vector<std::string> &);
	bool negate_method(int id, base_stream &,
			 const std::vector<std::string> &);

	bool output_info(base_stream &, const std::vector<std::string> &) const;

	void removed_interface(interface *);

	uint32_t registry_prefix_count() const { return m_trie.size(); }

	struct visitor {
		const inet6_addr &addr() const;
		prefix *entry() const;

		mrib_trie::const_iterator i;
		prefix *p;

		bool bestmetric;
		mrib_origin *owner;
	};

	bool visit_best_metric(visitor &) const;
	bool visit_origin(visitor &, mrib_origin *) const;
	bool visit_next(visitor &) const;

private:
	mrib_trie m_trie;
	objpool<mrib_node> m_trie_nodes;

	void event(int, void *);

	void insert_prefix_in_node(mrib_node *n, prefix *p);
	void remove_prefix_from_node(prefix *);

	mrib_node *prefix_lookup_y(const inet6_addr &, const inet6_addr &) const;
	mrib_node *prefix_lookup_y(const inet6_addr &) const;

	void invalidate_node_watchers(mrib_node *);

	void prefix_lost(const inet6_addr &, metric_def, const prefix &);

	mrib_node *grab_node(mrib_node *, mrib_watcher_base *, bool);
	prefix *grab_prefix(prefix *);
	void dec_node_refcount(mrib_node *);
	void dec_prefix_refcount(prefix *);

	bool local(const std::vector<std::string> &);
	bool negate_local(const std::vector<std::string> &);
	bool confprefix(const std::vector<std::string> &);
	bool negate_prefix(const std::vector<std::string> &);

	void dump_node_watchers(base_stream &out) const;

	typedef std::list<mrib_origin *> listeners;
	listeners m_listeners;

	mrib_connected_origin *m_local;
	mrib_static_origin *m_static;

	friend class mrib_watcher_base;
};

/*!
 * MRIB origin interface. Only modules implementing this interface
 * may feed new mrib entries
 */
class mrib_origin {
public:
	virtual ~mrib_origin();

	virtual const char *description() const = 0;

	virtual void output_prefix_info(base_stream &, const mrib_def::prefix &) const;

	virtual void prefix_added(const inet6_addr &, mrib_def::metric_def,
					const mrib_def::prefix &);
	virtual void prefix_lost(const inet6_addr &, mrib_def::metric_def,
					const mrib_def::prefix &);

	virtual void return_prefix(mrib_def::prefix *) = 0;
};

/*!
 * provides a mrib origin for directly connected prefixes
 */
class mrib_connected_origin : public mrib_origin {
public:
	const char *description() const;

	void register_prefix(const inet6_addr &, interface *);
	void unregister_prefix(const inet6_addr &, interface *);

	void return_prefix(mrib_def::prefix *);

private:
	typedef std::pair<interface *, mrib_def::prefix *> interface_prefix;
	typedef std::map<inet6_addr, interface_prefix> regdef;

	regdef _reg;
};

class mrib_static_origin : public mrib_origin {
public:
	const char *description() const;
	void return_prefix(mrib_def::prefix *);
};

class mrib_watcher_target {
public:
	virtual ~mrib_watcher_target() {}

	virtual const inet6_addr &target_group() const = 0;
	virtual const in6_addr &target_destination() const = 0;
};

/*!
 * provides a callback based MRIB entry watcher
 */
class mrib_watcher_base : public event_sink {
public:
	mrib_watcher_base(mrib_watcher_target *);
	virtual ~mrib_watcher_base();

	void release();

	const in6_addr &target() const { return _target->target_destination(); }
	const inet6_addr &group() const { return _target->target_group(); }
	const in6_addr &nexthop() const { return _nexthop; }

	void invalidate();

	interface *intf() const;

	uint32_t prefix_protocol() const;
	uint32_t prefix_metric() const;

	virtual void entry_changed() = 0;

	enum {
		Invalidated = 100
	};

	void event(int, void *);

private:
	void nexthop_changed();

	void invalidated();

	mrib_watcher_target *_target;

	mrib_def::mrib_node *_rec;
	mrib_def::prefix *_prefix;

	in6_addr _nexthop;
	uint32_t _metric, _protocol;
	interface *_intf;

	mrib_watcher_base *wnext;

	/* dont add the invalidate task twice */
	bool pending_update;

	friend class mrib_def;
};

/*!
 * provides a template based mrib watcher
 */
template<typename Holder>
class mrib_watcher : public mrib_watcher_base {
public:
	typedef std::mem_fun_t<void, Holder> callback_def;

	mrib_watcher(Holder *, callback_def);

	void entry_changed();

private:
	Holder *_h;
	callback_def _cb;
};

template<typename H> inline mrib_watcher<H>::mrib_watcher(H *h, mrib_watcher<H>::callback_def c)
	: mrib_watcher_base(h), _h(h), _cb(c) {}

template<typename H> inline void mrib_watcher<H>::entry_changed() {
	_cb(_h);
}

#endif


/*
 * Multicast Routing Daemon (MRD)
 *   mrib.cpp
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

#include <stdlib.h>
#include <mrd/mrd.h>
#include <mrd/mrib.h>
#include <mrd/interface.h>

#include <mrd/support/objpool.h>
#include <mrd/support/lists.h>

enum {
	mrib_method_local = 1000,
	mrib_method_prefix,
	mrib_method_summary,
	mrib_method_internal_ptree,
	mrib_method_internal_ptree_graph,
	mrib_method_node_watchers,
};

static const method_info mrib_methods[] = {
	{ "local", "Add a local prefix",
		mrib_method_local, false, property_def::NEGATE },
	{ "prefix", "Add a static MRIB entry",
		mrib_method_prefix, false, property_def::NEGATE },
	{ "static", "Add a static MRIB entry",
		mrib_method_prefix, false, property_def::NEGATE },
	{ "summary", "Displays a entry summary",
		mrib_method_summary, true, 0 },
	{ "internal-ptree", 0,
		mrib_method_internal_ptree, true, property_def::COMPLETE_M },
	{ "internal-ptree-graph", 0,
		mrib_method_internal_ptree_graph, true, property_def::COMPLETE_M },
	{ "node-watchers", 0,
		mrib_method_node_watchers, true, property_def::COMPLETE_M },
	{ 0 }
};

static objpool<mrib_def::prefix> _static_prefix_pool(128);

static inet6_addr _any;

struct static_prefix : mrib_def::prefix, public mrib_watcher_target {
	static_prefix(mrib_origin *);

	const inet6_addr &target_group() const { return _any; }
	const in6_addr &target_destination() const { return nexthop; }

	void check_nexthop();
	void nexthop_changed();

	mrib_watcher<static_prefix> global_watcher;
};

mrib_def::prefix::prefix(mrib_origin *own, uint32_t dist)
	: nexthop(in6addr_any), intf(0), owner(own), flags(0), distance(dist),
	  metric(0), refcount(0), trie_owner(0), next(0) {
	creation = time(0);
}

static_prefix::static_prefix(mrib_origin *owner)
	: mrib_def::prefix(owner),
	  global_watcher(this, std::mem_fun(&static_prefix::nexthop_changed)) {
	/* empty */
}

void static_prefix::check_nexthop() {
	if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop)
		&& !IN6_IS_ADDR_LINKLOCAL(&nexthop)) {
		global_watcher.invalidate();
	}
}

void static_prefix::nexthop_changed() {
	intf = global_watcher.intf();
}

mrib_origin::~mrib_origin() {
	/* empty */
}

void mrib_origin::prefix_added(const inet6_addr &, mrib_def::metric_def,
			       const mrib_def::prefix &) {
	/* empty */
}

void mrib_origin::prefix_lost(const inet6_addr &, mrib_def::metric_def,
			      const mrib_def::prefix &) {
	/* empty */
}

void mrib_origin::output_prefix_info(base_stream &,
				     const mrib_def::prefix &) const {
	/* empty */
}

mrib_def::mrib_def(node *m)
	: node(m, "mrib"), m_trie(/*objpool<ptree_node>(512)*/), m_trie_nodes(512) {
	m_local = 0;
	m_static = 0;
}

mrib_def::~mrib_def() {
	delete m_static;
	m_static = 0;
	delete m_local;
	m_local = 0;

	m_trie.clear();
}

bool mrib_def::check_startup() {
	if (!node::check_startup())
		return false;

	import_methods(mrib_methods);

	m_local = new mrib_connected_origin();
	if (!m_local)
		return false;

	m_static = new mrib_static_origin();
	if (!m_static)
		return false;

	/* always maintain a ::/0 node in the tree to accomodate
	 * for parent-less watchers */
	mrib_node *root = m_trie_nodes.request_obj();
	if (!root)
		return false;

	root->refcount = 1;
	root->prefix = inet6_addr::any();
	root->head = 0;
	root->watchhead = 0;

	return m_trie.insert(root) == root;
}

void mrib_def::shutdown() {
	origin_lost(m_static);
	origin_lost(m_local);
}

const char *mrib_def::description() const {
	return "Multicast Routing Information Base";
}

void mrib_def::event(int type, void *param) {
	if (type != mrd::InterfaceStateChanged) {
		node::event(type, param);
		return;
	}

	interface *intf = (interface *)param;

	for (mrib_trie::iterator i = m_trie.begin(); i != m_trie.end(); ++i) {
		if (i->head && i->head->intf == intf) {
			invalidate_node_watchers(&(*i));
		}
	}
}

const mrib_def::prefix *mrib_def::resolve_nexthop(const inet6_addr &src,
						  const inet6_addr &grp,
						  inet6_addr &result) const {
	const prefix *p = prefix_lookup(src, grp);

	if (p) {
		result = p->nexthop;
		if (result.is_any())
			result = src;
	}

	return p;
}

const mrib_def::prefix *mrib_def::prefix_lookup(const inet6_addr &source,
						const inet6_addr &group) const {
	mrib_node *n = prefix_lookup_y(source, group);

	if (!n)
		return 0;

	/* best prefix is always at head */
	return n->head;
}

mrib_def::prefix *mrib_def::get_prefix(const inet6_addr &source,
				       mrib_origin *origin) const {
	mrib_node *n = m_trie.search(source);

	if (!n)
		return 0;

	if (origin == NULL) {
		if (n->head != NULL && n->head->next == NULL)
			return n->head;
	}

	for (prefix *curr = n->head; curr; curr = curr->next) {
		if (curr->owner == origin) {
			return curr;
		}
	}

	return 0;
}

bool mrib_def::visit_best_metric(visitor &v) const {
	if (m_trie.empty())
		return false;

	v.i = m_trie.begin();
	v.p = v.i->head;

	if (!v.p) {
		++v.i;
		if (v.i != m_trie.end())
			v.p = v.i->head;
	}

	v.bestmetric = true;
	v.owner = 0;

	return v.p != 0;
}

bool mrib_def::visit_origin(visitor &v, mrib_origin *owner) const {
	if (m_trie.empty())
		return false;

	v.i = m_trie.begin();
	v.bestmetric = false;
	v.owner = owner;

	v.p = v.i->head;

	if (!v.p) {
		++v.i;
		if (v.i != m_trie.end())
			v.p = v.i->head;
	}

	if (!v.p)
		return false;

	while (v.i != m_trie.end() && v.p->owner != owner) {
		v.p = v.p->next;
		if (!v.p) {
			++v.i;
			if (v.i == m_trie.end())
				return false;
			v.p = v.i->head;
		}
	}

	return v.p != 0;
}

bool mrib_def::visit_next(visitor &v) const {
	while (1) {
		if (v.p)
			v.p = v.p->next;

		if (!v.p) {
			++ v.i;
			if (v.i == m_trie.end())
				return false;
			v.p = v.i->head;
			if (v.bestmetric)
				break;
		} else {
			if (v.bestmetric) {
				v.p = 0;
				continue;
			}
			if (v.owner && v.p->owner == v.owner)
				break;
		}
	}

	return true;
}

const inet6_addr &mrib_def::visitor::addr() const {
	return i->prefix;
}

mrib_def::prefix *mrib_def::visitor::entry() const {
	return p;
}

mrib_def::mrib_node *mrib_def::prefix_lookup_y(const inet6_addr &source,
					       const inet6_addr &group) const {
	/* group is ignored for now */
	return prefix_lookup_y(source);
}

mrib_def::mrib_node *mrib_def::prefix_lookup_y(const inet6_addr &source) const {
	mrib_node *n = m_trie.longest_match(source);

	return n;
}

void mrib_def::insert_prefix_in_node(mrib_node *n, prefix *p) {
	prefix *curr = n->head, *prev = 0;

	/* first check the proper place based on distance */
	while (curr && curr->distance < p->distance) {
		prev = curr;
		curr = curr->next;
	}

	if (prev && prev->distance == p->distance) {
		/* if distance matches, take metric into place */
		curr = prev;
		while (curr && curr->metric <= p->metric) {
			prev = curr;
			curr = curr->next;
		}
	}

	list_insert_after(n->head, prev, p);
}

bool mrib_def::install_prefix(const inet6_addr &src, prefix *p) {
	if (!p)
		return false;

	if (should_log(EXTRADEBUG))
		log().xprintf("(MRIB) Added entry %{Addr} [%u/%u, %s].\n",
			      src, p->distance, p->metric, p->owner->description());

	bool newprefix = false;

	mrib_node *n = m_trie.search(src);

	if (!n) {
		n = m_trie_nodes.request_obj();
		if (!n)
			return false;

		n->refcount = 1;
		n->prefix = src;
		n->head = 0;
		n->watchhead = 0;

		m_trie.insert(n);
		/* assert(m_trie.insert(n)); */

		newprefix = true;
	}

	/* prepare node for insertion */
	p->trie_owner = n;

	insert_prefix_in_node(n, p);

	p->refcount ++;

	if (newprefix) {
		/* if we installed a new prefix, notify all watching with
		 * a used entry less specific than the current prefix */
		mrib_node *parent = m_trie.get_parent_node(n);
		if (parent) {
			/* this really is a new more specific prefix,
			 * invalidate all watchers using the less specific
			 * prefix (the parent) */
			invalidate_node_watchers(parent);
		}
	} else if (n->head == p) {
		/* if the new entry is the best entry for the
		 * prefix, notify all watching this prefix */
		invalidate_node_watchers(n);
	}

	for (listeners::iterator i = m_listeners.begin();
				i != m_listeners.end(); ++i) {
		if (p->owner != *i)
			(*i)->prefix_added(src, p->metric, *p);
	}

	return true;
}

void mrib_def::invalidate_node_watchers(mrib_node *n) {
	mrib_watcher_base *w = n->watchhead;

	while (w) {
		mrib_watcher_base *c = w;
		w = w->wnext;

		c->invalidate();
	}
}

void mrib_def::remove_prefix_from_node(prefix *p) {
	list_search_remove(p->trie_owner->head, p);
}

void mrib_def::update_prefix(prefix *p) {
	if (!p->trie_owner)
		return;

	bool wasbest = p->is_best_entry();

	remove_prefix_from_node(p);
	insert_prefix_in_node(p->trie_owner, p);

	if (wasbest != p->is_best_entry())
		invalidate_node_watchers(p->trie_owner);
}

void mrib_def::remove_prefix(prefix *p) {
	if (!p || !p->trie_owner) {
		return;
	}

	inet6_addr prefix = p->trie_owner->prefix;

	remove_prefix_from_node(p);

	mrib_node *invn = p->trie_owner;
	p->trie_owner = 0;

	if (!invn->head && invn->prefix.prefixlen > 0) {
		/* if not root, no longer need the mrib node */
		m_trie.remove(invn);
	} else {
		/* as we still need the node, prevent removal below */
		invn->refcount ++;
	}

	if (should_log(EXTRADEBUG))
		log().xprintf("(MRIB) Removed entry %{Addr} [%s].\n",
			      prefix, p->owner->description());

	invalidate_node_watchers(invn);
	dec_node_refcount(invn);

	prefix_lost(prefix, p->metric, *p);

	dec_prefix_refcount(p);
}

mrib_def::mrib_node *mrib_def::grab_node(mrib_node *n, mrib_watcher_base *w,
					 bool include) {
	if (!n)
		return 0;

	if (include) {
		w->wnext = n->watchhead;
		n->watchhead = w;
		n->refcount ++;

		return n;
	} else {
		mrib_watcher_base *prev = 0, *curr = n->watchhead;

		while (curr && curr != w) {
			prev = curr;
			curr = curr->wnext;
		}

		if (prev)
			prev->wnext = w->wnext;
		else
			n->watchhead = w->wnext;

		dec_node_refcount(n);

		return 0;
	}
}

mrib_def::prefix *mrib_def::grab_prefix(prefix *p) {
	p->refcount ++;
	return p;
}

void mrib_def::dec_node_refcount(mrib_node *n) {
	if (!n)
		return;

	/* assert(n->refcount > 0); */

	n->refcount --;
	if (n->refcount == 0)
		m_trie_nodes.return_obj(n);
}

void mrib_def::dec_prefix_refcount(prefix *p) {
	if (!p)
		return;

	/* assert(p->refcount > 0); */

	p->refcount --;
	if (p->refcount == 0)
		p->owner->return_prefix(p);
}

void mrib_def::install_listener(mrib_origin *orig) {
	m_listeners.push_back(orig);

	for (mrib_trie::iterator i = m_trie.begin(); i != m_trie.end(); ++i) {
		for (prefix *curr = i->head; curr; curr = curr->next) {
			if (curr->owner != orig)
				orig->prefix_added(i->prefix, curr->metric, *curr);
		}
	}
}

void mrib_def::origin_lost(mrib_origin *orig) {
	listeners::iterator k = std::find(m_listeners.begin(),
					  m_listeners.end(), orig);

	if (k != m_listeners.end()) {
		m_listeners.erase(k);
	}

	mrib_trie::iterator i = m_trie.begin();

	int count = 0;

	while (i != m_trie.end()) {
		prefix *curr = i->head;

		++i;

		while (curr) {
			prefix *c = curr;
			curr = curr->next;

			if (c->owner == orig) {
				remove_prefix(c);
				count++;
			}
		}
	}

	if (should_log(DEBUG))
		log().xprintf("(MRIB) Lost origin %s, released %i "
			      "prefixes.\n", orig->description(), count);
}

void mrib_def::removed_interface(interface *intf) {
	mrib_trie::iterator i = m_trie.begin();

	int count = 0;

	while (i != m_trie.end()) {
		prefix *curr = i->head;

		++i;

		while (curr) {
			prefix *_p = curr;
			curr = curr->next;

			if (_p->intf == intf) {
				remove_prefix(_p);
				count++;
			}
		}
	}

	if (count == 0)
		return;

	g_mrd->log().xprintf("(MRIB) Removal of %s forced the release "
			     "of %i prefixes.\n", intf->name(), count);
}

void mrib_def::prefix_lost(const inet6_addr &addr, metric_def metric,
			   const prefix &p) {
	for (listeners::iterator i = m_listeners.begin();
				i != m_listeners.end(); ++i) {
		(*i)->prefix_lost(addr, metric, p);
	}
}

void mrib_def::invalidate_watcher(mrib_watcher_base *watch) {
	if (watch && !watch->pending_update) {
		watch->pending_update = true;
		g_mrd->register_task(watch, mrib_watcher_base::Invalidated, 0);
	}
}

mrib_watcher_base::mrib_watcher_base(mrib_watcher_target *t)
	: _target(t), _rec(0), _prefix(0), _nexthop(in6addr_any),
	  _metric(0xffffffff), _protocol(1000), _intf(0), wnext(0),
	  pending_update(false) {
}

mrib_watcher_base::~mrib_watcher_base() {
	release();
}

void mrib_watcher_base::event(int type, void *) {
	if (type != Invalidated)
		return;

	/* whaaa? */
	if (!pending_update)
		return;

	pending_update = false;

	invalidated();
}

void mrib_watcher_base::release() {
	g_mrd->clear_tasks(this);

	_rec = g_mrd->mrib().grab_node(_rec, this, false);
	g_mrd->mrib().dec_prefix_refcount(_prefix);
	_prefix = 0;

	_nexthop = in6addr_any;
	_metric = 0xffffffff;
	_protocol = 1000;
	_intf = 0;
}

void mrib_watcher_base::invalidated() {
	mrib_def::mrib_node *m =
		g_mrd->mrib().prefix_lookup_y(target(), group());

	mrib_def::prefix *prev = _prefix;

	if (prev) {
		/* delay the removal of prefix */
		prev->refcount ++;
	}

	release();

	/* we always grab it, we want to know what is going on */
	_rec = g_mrd->mrib().grab_node(m, this, true);

	mrib_def &mrib = g_mrd->mrib();

	if (!m || !m->head) {
		if (prev) {
			if (mrib.should_log(EXTRADEBUG)) {
				mrib.log().xprintf(
					"Target %{addr}, has no prefix "
					"record to use.\n", target());
			}

			nexthop_changed();
		}
	} else if (prev != m->head) {
		_prefix = g_mrd->mrib().grab_prefix(m->head);

		if (_prefix->is_valid()) {
			_metric = _prefix->metric;
			_protocol = _prefix->distance;

			if (mrib.should_log(EXTRADEBUG)) {
				mrib.log().xprintf("Target %{addr} using entry"
						   " %{Addr} [%s].\n", target(),
						   _rec->prefix, _prefix->owner->description());
			}
		} else {
			if (mrib.should_log(EXTRADEBUG)) {
				mrib.log().xprintf("Target %{addr}, has a "
						   "prefix record but is "
						   "disabled.\n", target());
			}

			_prefix = 0;
		}

		nexthop_changed();
	}

	g_mrd->mrib().dec_prefix_refcount(prev);
}

void mrib_watcher_base::invalidate() {
	g_mrd->mrib().invalidate_watcher(this);
}

interface *mrib_watcher_base::intf() const {
	return _intf;
}

uint32_t mrib_watcher_base::prefix_protocol() const {
	return _protocol;
}

uint32_t mrib_watcher_base::prefix_metric() const {
	return _metric;
}

void mrib_watcher_base::nexthop_changed() {
	_intf = _prefix ? _prefix->intf : 0;

	if (_prefix) {
		_nexthop = _prefix->nexthop;
		if (IN6_IS_ADDR_UNSPECIFIED(&_nexthop))
			_nexthop = target();
	} else {
		_nexthop = in6addr_any;
	}

	entry_changed();
}

bool mrib_def::call_method(int id, base_stream &out,
			   const std::vector<std::string> &args) {
	switch (id) {
	case mrib_method_local:
		return local(args);
	case mrib_method_prefix:
		return confprefix(args);
	case mrib_method_summary:
		out.xprintf("MRIB prefix count: %u\n", m_trie.size());
		return true;
	case mrib_method_internal_ptree:
		m_trie.dump_internal_tree(out);
		return true;
	case mrib_method_internal_ptree_graph:
		m_trie.dump_internal_tree_graphviz(out);
		return true;
	case mrib_method_node_watchers:
		dump_node_watchers(out);
		return true;
	}

	return node::call_method(id, out, args);
}

bool mrib_def::negate_method(int id, base_stream &out,
			     const std::vector<std::string> &args) {
	switch (id) {
	case mrib_method_local:
		return negate_local(args);
	case mrib_method_prefix:
		return negate_prefix(args);
	}

	return node::negate_method(id, out, args);
}

void mrib_def::dump_node_watchers(base_stream &out) const {
	for (mrib_trie::const_iterator i = m_trie.begin(); i != m_trie.end(); ++i) {
		out.xprintf("%{Addr} has", i->prefix);

		if (i->watchhead) {
			mrib_watcher_base *w = i->watchhead;
			while (w) {
				out.xprintf(" %{addr}", w->target());
				w = w->wnext;
			}
		} else {
			out.write(" <none>");
		}

		out.newl();
	}
}

bool mrib_def::local(const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	bool local_only = false;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		if (*i == "no-export") {
			local_only = true;
		} else if (*i == "export") {
			local_only = false;
		} else {
			inet6_addr addr;
			if (addr.set(*i)) {
				prefix *pinfo = new static_prefix(m_static);
				if (pinfo) {
					pinfo->metric = 0x1000;
					if (local_only)
						pinfo->flags |= prefix::NO_EXPORT;
					install_prefix(addr, pinfo);
				}
			} else {
				return false;
			}
		}
	}

	return true;
}

bool mrib_def::negate_local(const std::vector<std::string> &args) {
	if (args.size() != 1)
		return false;

	inet6_addr prfx;
	if (!prfx.set(args[0].c_str()))
		return false;

	remove_prefix(get_prefix(prfx, m_local));

	return true;
}

bool mrib_def::confprefix(const std::vector<std::string> &args) {
	/* Needs at least 3 args */
	if (args.size() < 3)
		return false;

	inet6_addr pfix;

	if (!pfix.set(args[0]))
		return false;

	inet6_addr nh;
	interface *dev = 0;
	uint32_t metric = 100;
	bool local_only = true;

	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		if (*i == "via") {
			++i;
			if (i == args.end() || !nh.set(*i))
				return false;
		} else if (*i == "dev") {
			++i;
			if (i == args.end())
				return false;
			dev = g_mrd->get_interface_by_name(i->c_str());
			if (!dev)
				return false;
		} else if (*i == "metric") {
			++i;
			if (i == args.end())
				return false;
			char *end;
			metric = strtoul(i->c_str(), &end, 10);
			if (*end)
				return false;
		} else if (*i == "export") {
			local_only = false;
		}
	}

	/* No nexthop and no dev supplied, fail. */
	if (nh.is_any() && !dev)
		return false;

	if (nh.is_linklocal() && !dev)
		return false;

	static_prefix *pinfo = new static_prefix(m_static);
	if (pinfo) {
		pinfo->distance = 1;
		pinfo->metric = metric;
		pinfo->nexthop = nh;
		pinfo->intf = dev;
		if (local_only)
			pinfo->flags |= prefix::NO_EXPORT;

		pinfo->check_nexthop();

		install_prefix(pfix, pinfo);
	} else {
		return false;
	}

	return true;
}

bool mrib_def::negate_prefix(const std::vector<std::string> &args) {
	if (args.size() < 1)
		return false;

	inet6_addr prfx;
	if (!prfx.set(args[0].c_str()))
		return false;

	inet6_addr nh;
	interface *dev = 0;
	uint32_t metric = 0xffffffff;

	std::vector<std::string>::const_iterator j = args.begin();
	++j;

	for (; j != args.end(); ++j) {
		if (*j == "via") {
			++j;
			if (j == args.end() || !nh.set(*j))
				return false;
		} else if (*j == "dev") {
			++j;
			if (j == args.end())
				return false;
			dev = g_mrd->get_interface_by_name(j->c_str());
			if (!dev)
				return false;
		} else if (*j == "metric") {
			++j;
			if (j == args.end())
				return false;
			char *end;
			metric = strtoul(j->c_str(), &end, 10);
			if (*end)
				return false;
		} else {
			return false;
		}
	}

	mrib_node *m = m_trie.search(prfx);
	if (!m)
		return false;

	prefix *curr = m->head;

	while (curr) {
		prefix *_p = curr;
		curr = curr->next;

		if (!nh.is_any() && !(_p->nexthop == nh))
			continue;
		if (dev && _p->intf != dev)
			continue;
		if (metric < 0xffffffff && _p->metric != metric)
			continue;

		remove_prefix(_p);
	}

	return true;
}

const char *mrib_connected_origin::description() const {
	return "Directly Connected";
}

const char *mrib_static_origin::description() const {
	return "Static";
}

void mrib_connected_origin::register_prefix(const inet6_addr &addr,
					 interface *intf) {
	std::pair<regdef::iterator, bool> res
		= _reg.insert(std::make_pair(addr,
				std::make_pair(intf, (mrib_def::prefix *)0)));

	if (res.second) {
		mrib_def::prefix *pinfo = _static_prefix_pool.request_obj(this);
		if (pinfo) {
			pinfo->distance = 0;
			pinfo->metric = 0;
			pinfo->flags = mrib_def::prefix::NO_EXPORT;
			pinfo->intf = intf;
			g_mrd->mrib().install_prefix(addr, pinfo);

			res.first->second.second = pinfo;
		} else {
			_reg.erase(res.first);
		}
	}
}

void mrib_connected_origin::unregister_prefix(const inet6_addr &addr,
					   interface *intf) {
	regdef::iterator i = _reg.find(addr);

	if (i != _reg.end()) {
		if (i->second.first == intf) {
			g_mrd->mrib().remove_prefix(i->second.second);
			_reg.erase(i);
		}
	}
}

void mrib_static_origin::return_prefix(mrib_def::prefix *p) {
	delete (static_prefix *)p;
}

void mrib_connected_origin::return_prefix(mrib_def::prefix *p) {
	_static_prefix_pool.return_obj(p);
}

bool mrib_def::output_info(base_stream &ctx,
			   const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	ctx.writeline("MRIB");

	ctx.inc_level();

	for (mrib_trie::const_iterator m = m_trie.begin(); m != m_trie.end(); ++m) {
		for (prefix *curr = m->head; curr; curr = curr->next) {
			ctx.xprintf("Prefix %{Addr} Cost: %u/%u, %s%s\n",
				    m->prefix, (uint32_t)curr->distance,
				    (uint32_t)curr->metric,
				    curr->owner->description(),
				    (curr->flags & prefix::NO_EXPORT) ? " L" : "");

			ctx.inc_level();

			if (!IN6_IS_ADDR_UNSPECIFIED(&curr->nexthop))
				ctx.xprintf("Nexthop: %{addr}\n", curr->nexthop);

			if (curr->intf) {
				ctx.xprintf("Interface: %s", curr->intf->name());
				if (curr->owner == m_static
					&& !IN6_IS_ADDR_UNSPECIFIED(&curr->nexthop)
					&& !IN6_IS_ADDR_LINKLOCAL(&curr->nexthop)) {
					static_prefix *p = (static_prefix *)curr;
					ctx.xprintf(" (via %{Addr}", p->global_watcher._rec->prefix);
					if (!p->global_watcher.pending_update)
						ctx.xprintf(", %s", p->global_watcher._prefix->owner->description());
					ctx.write(")");
				}

				if (!curr->intf->up())
					ctx.write(", Disabled");

				ctx.newl();
			} else {
				ctx.writeline("Interface: None");
			}

			curr->owner->output_prefix_info(ctx, *curr);

			ctx.dec_level();
		}
	}

	ctx.dec_level();

	return true;
}



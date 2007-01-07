/*
 * Multicast Routing Daemon (MRD)
 *   mld_ext.cpp
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

#include <mrdpriv/mld/def.h>
#include <mrdpriv/mld/router.h>

/* method definition */

enum {
	mld_ext_router_static_listener = 4000,
	mld_ext_router_local_static,
};

static const method_info mld_ext_router_methods[] = {
	{ "static-listener", "Adds a new static listener to the specified interface",
		mld_ext_router_static_listener, false, property_def::NEGATE },
	{ "local-static", "Joins the specific group in the router's loopback interface",
		mld_ext_router_local_static, false, property_def::NEGATE },
	{ 0 }
};

struct create_group_mld_ext_context : mrd::create_group_context {
	int mld_mode;
	address_set mld_sources;
};

/* module definition */

class mld_ext_module : public mrd_module {
public:
	mld_ext_module(mrd *m, void *);

	bool check_startup();
	void shutdown();
};

module_entry(mld_ext, mld_ext_module);

/* mld re-definitions */

class mld_ext_group_interface : public mld_group_interface {
public:
	mld_ext_group_interface(mld_group *, mld_interface *);
	~mld_ext_group_interface();

	void send_mld_query(bool, const address_set &);

	void change_listener_filter(const in6_addr &, int mode,
				    const address_set &);
	void remove_listener(const in6_addr &);

	struct fake_listener {
		fake_listener(mld_ext_group_interface *, const in6_addr &);

		void send_fake_report();

		mld_ext_group_interface *owner;

		/* Fake Listener address */
		in6_addr reporter;

		/* MLD filter */
		int mode;
		address_set sources;

		/* Report timer */
		timer<fake_listener> rtimer;
	};

	void send_fake_report(int, fake_listener &);

private:
	typedef std::vector<fake_listener *> listeners;

	listeners m_listeners;
};

class mld_ext_group : public mld_group {
public:
	mld_ext_group(router *);

	group_interface *instantiate_group_interface(interface *);
};

class mld_ext_router : public mld_router {
public:
	bool check_startup();

	bool call_method(int, base_stream &, const std::vector<std::string> &);
	bool negate_method(int, base_stream &, const std::vector<std::string> &);

	bool do_static(const in6_addr &group, interface *intf,
		       const in6_addr &reporter, int mode, const address_set &);

	void event(int, void *);

	mld_group *allocate_group();
};

extern mld_router *mld;

/* implementation */

mld_ext_module::mld_ext_module(mrd *m, void *arg)
	: mrd_module(m, arg) {
}

bool mld_ext_module::check_startup() {
	mld = new mld_ext_router();
	if (!mld)
		return false;
	if (!g_mrd->register_router(mld)) {
		delete mld;
		mld = 0;
	}
	return mld != 0;
}

void mld_ext_module::shutdown() {
	g_mrd->unregister_router(mld);
	mld->shutdown();
	delete mld;
	mld = 0;
}

mld_ext_group_interface::mld_ext_group_interface(mld_group *gr, mld_interface *gintf)
	: mld_group_interface(gr, gintf) {
}

mld_ext_group_interface::~mld_ext_group_interface() {
	for (listeners::iterator i = m_listeners.begin();
			i != m_listeners.end(); ++i) {
		delete *i;
	}

	m_listeners.clear();
}

void mld_ext_group_interface::send_mld_query(bool general, const address_set &srcs) {
	mld_group_interface::send_mld_query(general, srcs);

	/* respond in half the time the router gives us */
	uint32_t tvalue = g_intf->conf()->last_listener_query_interval() / 2;

	/* refresh all local fake listeners state */
	for (listeners::iterator i = m_listeners.begin();
				i != m_listeners.end(); ++i) {
		fake_listener *l = *i;

		/* only update time if we had a larger interval */
		if (l->rtimer.time_left() > tvalue)
			l->rtimer.update(tvalue, false);
	}
}

void mld_ext_group_interface::change_listener_filter(const in6_addr &addr,
						     int mode,
						     const address_set &sources) {
	bool leaving = (mode == MLD_SSM_CHANGE_TO_INCLUDE) && sources.empty();

	for (listeners::iterator i = m_listeners.begin();
				i != m_listeners.end(); ++i) {
		fake_listener *l = *i;

		/* already exists in list */
		if (l->reporter == addr) {
			int newmode = mode;

			if (newmode != l->mode) {
				newmode = (mode == MLD_SSM_MODE_INCLUDE) ?
					  MLD_SSM_CHANGE_TO_INCLUDE
					: MLD_SSM_CHANGE_TO_EXCLUDE;
			}

			l->mode = mode;
			l->sources = sources;

			send_fake_report(newmode, *l);

			if (leaving) {
				delete l;
				m_listeners.erase(i);
			}

			return;
		}
	}

	if (leaving)
		return;

	fake_listener *l = new fake_listener(this, addr);
	if (!l)
		return;

	l->mode = mode;
	l->sources = sources;

	send_fake_report(mode, *l);

	m_listeners.push_back(l);
}

void mld_ext_group_interface::remove_listener(const in6_addr &addr) {
	for (listeners::iterator i = m_listeners.begin();
				i != m_listeners.end(); ++i) {
		fake_listener *l = *i;

		if (l->reporter == addr) {
			delete l;
			m_listeners.erase(i);

			return;
		}
	}
}

void mld_ext_group_interface::send_fake_report(int mode, fake_listener &l) {
	refresh(l.reporter, mode, l.sources);

	l.rtimer.start_or_update(g_intf->conf()->query_interval() / 2, false);
}

mld_ext_group_interface::fake_listener::fake_listener(mld_ext_group_interface *gi,
						      const in6_addr &addr)
	: owner(gi), reporter(addr), mode(MLD_SSM_MODE_INCLUDE),
	  rtimer("fake listener rtimer", this,
		 std::mem_fun(&fake_listener::send_fake_report)) {
}

void mld_ext_group_interface::fake_listener::send_fake_report() {
	owner->send_fake_report(mode, *this);
}

mld_ext_group::mld_ext_group(router *rt)
	: mld_group(rt) {
}

group_interface *mld_ext_group::instantiate_group_interface(interface *intf) {
	mld_interface *mldintf = mld->get_interface(intf->index());

	if (mldintf)
		return new mld_ext_group_interface(this, mldintf);

	return 0;
}

bool mld_ext_router::check_startup() {
	if (!mld_router::check_startup())
		return false;

	import_methods(mld_ext_router_methods);

	return true;
}

bool mld_ext_router::call_method(int id, base_stream &out,
				const std::vector<std::string> &args) {
	if (id == mld_ext_router_static_listener) {
		if (args.size() < 4)
			return false;

		inet6_addr groupaddr;
		if (!groupaddr.set(args[0].c_str()))
			return false;

		inet6_addr reporter;
		if (!reporter.set(args[2].c_str()))
			return false;

		if (args[3] != "include" && args[3] != "exclude")
			return false;

		int mode = (args[3] == "include") ?
				MLD_SSM_MODE_INCLUDE : MLD_SSM_MODE_EXCLUDE;

		address_set sources;

		for (size_t k = 4; k < args.size(); k++) {
			inet6_addr addr;
			if (!addr.set(args[k].c_str()))
				return false;
			sources += addr.address();
		}

		interface *intf = g_mrd->get_interface_by_name(args[1].c_str());
		if (!intf)
			return false;

		return do_static(groupaddr, intf, reporter, mode, sources);
	} else if (id == mld_ext_router_local_static) {
		if (args.empty())
			return false;

		inet6_addr groupaddr;
		if (!groupaddr.set(args[0].c_str()))
			return false;

		interface *intf = g_mrd->get_loopback_interface();
		if (!intf)
			return false;

		address_set sources;
		int mode = MLD_SSM_MODE_EXCLUDE;

		if (args.size() > 1) {
			if (args[1] != "include" && args[1] != "exclude")
				return false;

			mode = (args[1] == "include") ?
					MLD_SSM_MODE_INCLUDE : MLD_SSM_MODE_EXCLUDE;

			address_set sources;

			for (size_t k = 2; k < args.size(); k++) {
				inet6_addr addr;
				if (!addr.set(args[k].c_str()))
					return false;
				sources += addr.address();
			}
		}

		return do_static(groupaddr, intf, in6addr_any, mode, sources);
	} else {
		return mld_router::call_method(id, out, args);
	}
}

bool mld_ext_router::do_static(const in6_addr &groupaddr, interface *intf,
			       const in6_addr &reporter, int mode,
			       const address_set &sources) {
	create_group_mld_ext_context *ctx =
				new create_group_mld_ext_context;
	if (!ctx)
		return false;

	ctx->iif = intf->index();
	ctx->groupaddr = groupaddr;
	ctx->requester = reporter;

	ctx->mld_mode = mode;
	ctx->mld_sources = sources;

	g_mrd->create_group(mld, this, ctx);

	return true;
}

bool mld_ext_router::negate_method(int id, base_stream &out,
				const std::vector<std::string> &args) {
	if (id == mld_ext_router_static_listener) {
		if (args.size() < 3)
			return false;

		inet6_addr groupaddr;
		if (!groupaddr.set(args[0].c_str()))
			return false;

		inet6_addr reporter;
		if (!reporter.set(args[2].c_str()))
			return false;

		interface *intf = g_mrd->get_interface_by_name(args[1].c_str());
		if (!intf)
			return false;

		mld_interface *mldintf = mld->get_interface(intf->index());
		if (!mldintf)
			return false;

		group *majorgrp = g_mrd->get_group_by_addr(groupaddr);
		if (!majorgrp)
			return false;

		mld_group *grp = (mld_group *)majorgrp->node_owned_by(mld);
		if (!grp)
			return false;

		mld_ext_group_interface *gintf =
			(mld_ext_group_interface *)grp->local_oif(mldintf);
		if (!gintf)
			return false;

		gintf->remove_listener(reporter);

		return true;
	} else if (id == mld_ext_router_local_static) {
		if (args.empty())
			return false;

		inet6_addr groupaddr;
		if (!groupaddr.set(args[0].c_str()))
			return false;

		interface *intf = g_mrd->get_loopback_interface();
		if (!intf)
			return false;

		mld_interface *mldintf = mld->get_interface(intf->index());
		if (!mldintf)
			return false;

		group *majorgrp = g_mrd->get_group_by_addr(groupaddr);
		if (!majorgrp)
			return false;

		mld_group *grp = (mld_group *)majorgrp->node_owned_by(mld);
		if (!grp)
			return false;

		mld_ext_group_interface *gintf =
			(mld_ext_group_interface *)grp->local_oif(mldintf);
		if (!gintf)
			return false;

		gintf->remove_listener(in6addr_any);

		return true;
	}

	return mld_router::negate_method(id, out, args);
}

void mld_ext_router::event(int ev, void *ptr) {
	if (ev == mrd::CreatedGroup) {
		create_group_mld_ext_context *ctx =
			(create_group_mld_ext_context *)ptr;

		if (!ctx || !ctx->result) {
			delete ctx;
			return;
		}

		mld_interface *mldintf = mld->get_interface(ctx->iif);
		if (!mldintf) {
			delete ctx;
			return;
		}

		mld_group *grp = (mld_group *)ctx->result->node_owned_by(mld);
		if (!grp) {
			delete ctx;
			return;
		}

		mld_ext_group_interface *gintf =
			(mld_ext_group_interface *)grp->local_oif(mldintf);
		if (!gintf) {
			delete ctx;
			return;
		}

		gintf->change_listener_filter(ctx->requester, ctx->mld_mode,
					      ctx->mld_sources);

		delete ctx;

		return;
	}

	mld_router::event(ev, ptr);
}

mld_group *mld_ext_router::allocate_group() {
	return new mld_ext_group(this);
}


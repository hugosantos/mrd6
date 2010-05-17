/*
 * Multicast Routing Daemon (MRD)
 *   interface.cpp
 *
 * Copyright (C) 2009 - Teemu Kiviniemi
 * Copyright (C) 2009 - CSC - IT Center for Science Ltd.
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

#include <mrd/interface.h>
#include <mrd/mrd.h>
#include <mrd/group.h>
#include <mrd/router.h>
#include <mrd/timers.h>

#include <string>

#include <cstring>
#include <errno.h>

#include <arpa/inet.h>

static const char *_kernel_state_names[] = {
	"Down",
	"No Link",
	"Up",
};

enum {
	intfconf_method_disable_router = 1000
};

static const method_info intfconf_methods[] = {
	{ "disable-router", "Disables the specified router in the interface",
		intfconf_method_disable_router, false, 0 },
	{ 0 }
};

intfconf::intfconf(const char *name)
	: conf_node(g_mrd->get_child("interfaces"), name) {
}

intfconf::~intfconf() {
	clear_childs();
}

bool intfconf::check_startup() {
	if (!conf_node::check_startup())
		return false;

	import_methods(intfconf_methods);

	return true;
}

void intfconf::remove_child_node(node *n) {
	delete (intfconf_node *)n;
}

void intfconf::fill_defaults() {
	instantiate_property_b("enabled", true);
	instantiate_property_b("install-mrib-prefixes", true);

	for (properties::iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (i->second.is_child())
			((intfconf_node *)i->second.get_node())->fill_defaults();
	}
}

void intfconf::property_changed(node *, const char *key) {
	if (!strcmp(key, "enabled")) {
		g_mrd->check_enabled_interfaces(this);
	}
}

bool intfconf::call_method(int id, base_stream &out,
			   const std::vector<std::string> &args) {
	switch (id) {
	case intfconf_method_disable_router:
		return disable_router(args);
	}

	return conf_node::call_method(id, out, args);
}

bool intfconf::disable_router(const std::vector<std::string> &args) {
	if (args.empty())
		return false;
	for (std::vector<std::string>::const_iterator i =
			args.begin(); i != args.end(); ++i) {
		disabled_routers.insert(*i);
	}
	return true;
}

bool intfconf::is_enabled() const {
	return get_property_bool("enabled");
}

bool intfconf::is_router_enabled(const char *name) const {
	return disabled_routers.find(name) == disabled_routers.end();
}

node *intfconf::next_similiar_node() const {
	if (!strcmp(name(), "all"))
		return 0;
	return g_mrd->default_interface_configuration();
}

node *intfconf::create_child(const char *name) {
	node *child = get_child(name);
	if (child)
		return child;

	properties::const_iterator i = m_properties.find(name);
	if (i != m_properties.end())
		return 0;

	router *rt = g_mrd->get_router(name);
	if (rt)
		child = rt->create_interface_configuration(this);

	if (!child || !child->check_startup()) {
		delete child;
		return 0;
	}

	return add_child(child);
}

void intfconf::update_interface_configuration(interface *intf) {
	intf->mif_conf = this;
}

intfconf_node::intfconf_node(intfconf *parent, const char *name)
	: conf_node(parent, name) {
}

node *intfconf_node::next_similiar_node() const {
	if (strcmp(parent()->name(), "all") == 0)
		return 0;
	return g_mrd->default_interface_configuration()->get_child(name());
}

interface_node::interface_node(router *rt)
	: node(0, rt->name()), n_owner(0), n_owner_router(rt) {}

interface_node::~interface_node() {
}

void interface_node::attached(interface *owner) {
	m_parent = owner;
	n_owner = owner;
}

void interface_node::dettached() {
	m_parent = 0;
	n_owner = 0;
}

bool interface_node::should_log(int level) const {
	if (owner() && owner()->should_log(level))
		return owner_router() && owner_router()->should_log(level);
	return false;
}

base_stream &interface_node::log() const {
	return owner_router()->log_router_desc(owner()->log());
}

interface::interface(intfconf *cnf, int indx, const char *ifname, int type, int mtu, int flags)
	: node(g_mrd->get_child("interface"), ifname) {

	memset(&mif_localaddr, 0, sizeof(mif_localaddr));

	mif_conf = cnf;

	mif_index = indx;
	mif_name = ifname;
	mif_type = type;
	mif_mtu = mtu;
	mif_flags = flags;

	mif_state = Down;
	mif_enabled = true;

	mif_localaddr.sin6_family = AF_INET6;
	mif_localaddr.sin6_scope_id = mif_index;

	mif_creationtime = tval::now();
}

interface::~interface() {
}

void interface::shutdown() {
	if (should_log(VERBOSE))
		log().xprintf("(MRD) Removing %s.\n", name());
}

base_stream &interface::log() const {
	return node::log().xprintf("[%s] ", name());
}

static const char *_type_name(int type, int flags) {
	switch (type) {
	case interface::Loopback:
		return "loopback";
	case interface::Ethernet:
		return "ethernet";
	case interface::PPP:
		return "ppp";
	case interface::Tunnel:
		return "tunnel";
	case interface::TUN:
		return "tun";
	case interface::IEEE1394:
		return "ieee1394";
	case interface::IEEE802_11:
		return "802.11";
	case interface::IEEE802_1Q:
		return "vlan";
	default:
		return "unknown";
	}
}

const char *interface::type_str() const {
	return _type_name(mif_type, mif_flags);
}

bool interface::is_multiaccess() const {
	/* We'll just take Ethernet for now */
	return mif_type == Ethernet;
}

bool interface::up(bool ignoremrd) const {
	if (state() == Up && mif_enabled) {
		if (ignoremrd)
			return true;
		return g_mrd->is_running();
	}

	return false;
}

void interface::change_state(kernel_state newstate) {
	if (mif_state == newstate)
		return;

	bool wasdown = !up();

	if (should_log(VERBOSE)) {
		log().xprintf("State changed: %s -> %s.\n",
			      _kernel_state_names[mif_state],
			      _kernel_state_names[newstate]);
	}

	mif_state = newstate;

	broadcast_change_state(wasdown);
}

/* Is the interface a virtual interface? */
bool interface::is_virtual() {
	return mif_type == IPv4_Translator;
}

void interface::broadcast_change_state(bool wasdown) {
	if (up() != !wasdown) {
		g_mrd->broadcast_interface_state_changed(this);
	}
}

void interface::set_enabled(bool newstate) {
	bool wasdown = !up();

	mif_enabled = newstate;

	broadcast_change_state(wasdown);
}

bool interface::attach_node(interface_node *node) {
	if (!add_child(node))
		return false;

	node->attached(this);

	for (std::set<inet6_addr>::const_iterator i = mif_linklocals.begin();
					i != mif_linklocals.end(); i++) {
		node->address_added_or_removed(true, *i);
	}

	for (std::set<inet6_addr>::const_iterator i = mif_globals.begin();
					i != mif_globals.end(); i++) {
		node->address_added_or_removed(true, *i);
	}

	return true;
}

void interface::dettach_node(interface_node *node) {
	interface_node *n = (interface_node *)get_child(node->name());

	if (n && n == node) {
		remove_child(node->name());
		node->dettached();
	}
}

interface_node *interface::node_owned_by(const router *rt) const {
	return (interface_node *)get_child(rt->name());
}

void interface::address_added_or_removed(bool isnew, const inet6_addr &addr) {
	// filter duplicates

	if (addr.is_any() || (isnew && mif_linklocals.find(addr) != mif_linklocals.end()))
		return;

	if (isnew && !addr.is_linklocal() && mif_globals.find(addr) != mif_globals.end())
		return;

	add_remove_address(isnew, addr);
}

void interface::add_remove_address(bool isnew, const inet6_addr &addr) {
	bool loopback = IN6_IS_ADDR_LOOPBACK(&addr.addr);

	if (loopback && mif_type != Loopback)
		return;

	if (isnew) {
		if (loopback || addr.is_linklocal()) {
			if (mif_linklocal.is_any()) {
				mif_linklocal = addr;
				mif_localaddr.sin6_addr = addr;
			}
			mif_linklocals.insert(addr);
		} else {
			mif_globals.insert(addr);

			if (addr.prefixlen < 128 && conf()->get_property_bool("install-mrib-prefixes")) {
				g_mrd->mrib().local().register_prefix(addr.prefix(), this);
			}
		}
	} else {
		if (loopback || addr.is_linklocal()) {
			std::set<inet6_addr>::iterator k = mif_linklocals.find(addr);
			if (k == mif_linklocals.end()) {
				return;
			}
			mif_linklocals.erase(k);
			if (mif_linklocal == addr) {
				if (mif_linklocals.empty()) {
					mif_linklocal = in6addr_any;
				} else {
					mif_linklocal = *mif_linklocals.begin();
				}
				mif_localaddr.sin6_addr = mif_linklocal.address();
			}
		} else {
			std::set<inet6_addr>::iterator k = mif_globals.find(addr);
			if (k == mif_globals.end()) {
				return;
			}
			mif_globals.erase(k);

			if (addr.prefixlen < 128) {
				g_mrd->mrib().local().unregister_prefix(addr.prefix(), this);
			}
		}
	}

	for (properties::iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (i->second.is_child()) {
			interface_node *in = (interface_node *)i->second.get_node();

			in->address_added_or_removed(isnew, addr);
		}
	}
}

bool interface::in_same_subnet(const in6_addr &addr) const {
	for (std::set<inet6_addr>::iterator i = mif_globals.begin(); i != mif_globals.end(); ++i) {
		if (i->matches(addr))
			return true;
	}
	return false;
}

static inline uint16_t inchksum(const void *data, uint32_t length) {
	long sum = 0;
	const uint16_t *wrd = reinterpret_cast<const uint16_t *>(data);
	long slen = static_cast<long>(length);

	while (slen > 1) {
		sum += *wrd++;
		slen -= 2;
	}

	if (slen > 0)
		sum += *reinterpret_cast<const uint8_t *>(wrd);

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return static_cast<uint16_t>(sum);
}

uint16_t ipv6_checksum(uint8_t protocol, const in6_addr &src, const in6_addr &dst, const void *data, uint16_t len) {
	struct {
		in6_addr src;
		in6_addr dst;
		uint16_t length;
		uint16_t zero1;
		uint8_t zero2;
		uint8_t next;
	}  __attribute__ ((packed)) pseudo;
	uint32_t chksum = 0;

	pseudo.src = src;
	pseudo.dst = dst;
	pseudo.length = htons(len);
	pseudo.zero1 = 0;
	pseudo.zero2 = 0;
	pseudo.next = protocol;

	chksum = inchksum(&pseudo, sizeof(pseudo));
	chksum += inchksum(data, len);

	chksum = (chksum >> 16) + (chksum & 0xffff);
	chksum += (chksum >> 16);

	chksum = static_cast<uint16_t>(~chksum);
	if (chksum == 0)
		chksum = 0xffff;

	return chksum;
}

bool interface::has_global(const in6_addr &addr) const {
	for (std::set<inet6_addr>::const_iterator i =
			mif_globals.begin(); i != mif_globals.end(); ++i) {
		if (i->address() == addr)
			return true;
	}
	return false;
}

const inet6_addr &interface::primary_addr() const {
	if (mif_globals.empty())
		return *mif_linklocals.begin();

	return *mif_globals.begin();
}

bool interface::output_info(base_stream &_out, const std::vector<std::string> &args) const {
	if (!args.empty())
		return false;

	_out.xprintf("Interface %s (%i) is ", name(), index());

	if (mif_enabled) {
		_out.write(mif_state == Up ? "Up" : "Down");
	} else {
		_out.write("Disabled");
	}

	_out.xprintf(" (Uptime: %{duration})\n",
		     time_duration(tval::now() - mif_creationtime));

	_out.inc_level();

	if (mif_linklocals.empty()) {
		_out.writeline("Link-Local: (None)");
	} else {
		bool first = mif_globals.empty();
		for (std::set<inet6_addr>::const_iterator i = mif_linklocals.begin();
				i != mif_linklocals.end(); ++i) {
			_out.xprintf("Link-Local: %{Addr}", *i);
			if (first) {
				_out.write(" <PRIMARY>");
				first = false;
			}
			_out.newl();
		}
	}

	bool first = true;
	for (std::set<inet6_addr>::const_iterator i = mif_globals.begin();
			i != mif_globals.end(); ++i) {
		_out.xprintf("Global: %{Addr}", *i);
		if (first) {
			_out.write(" <PRIMARY>");
			first = false;
		}
		_out.newl();
	}

	node::output_info(_out, std::vector<std::string>());

	_out.dec_level();

	return true;
}


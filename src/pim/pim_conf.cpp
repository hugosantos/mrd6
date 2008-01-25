/*
 * Multicast Routing Daemon (MRD)
 *   pim_conf.cpp
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

#include <mrdpriv/pim/router.h>
#include <mrdpriv/pim/interface.h>
#include <mrdpriv/pim/group.h>
#include <mrdpriv/pim/neighbour.h>
#include <mrdpriv/pim/def.h>

#include <mrd/mrd.h>

#include <unistd.h>
#include <errno.h>

#include <cmath>

struct pim_property {
	const char *name;
	uint32_t value;
	const char *description;
};

static pim_property pim_intf_props[] = {
	{ "hello-interval",		30000,
		"Sets the interval between PIM Hello messages" },
	{ "joinprune-interval",		60000,
		"Sets the interval between PIM Join/Prune periodic messages" },
	{ "data-timeout",		210000,
		"Sets the time after which a (S,G) state for an inactive source is deleted" },
	{ "register-supression-timeout", 60000,
		"Sets the Register-Stop state expiry time" },
	{ "probe-time",			5000,
		"Sets the time before a Register-Stop state expiring in which a probe should be sent" },
	{ "assert-timeout",		180000,
		"Sets the PIM Assert timeout" },
	{ "random-delay-join-timeout",	4500,	0 },
	{ "dr-priority",		1,	"Sets the interface DR priority" },
	{ "register-stop-rate-limit",	30,	0 },
	{ "register-stop-rate-timelen", 10000,	0 },
	{ "propagation-delay",		500,	0 },
	{ "override-interval",		2500,	0 },
	{ 0 }
};

static struct propval_enum::entry rp_rej_entries[] = {
	{ "register-stop",	pim_groupconf_node::RPRejRegisterStop },
	{ "silent-ignore",	pim_groupconf_node::RPRejSilentIgnore },
	{ "log-ignore",		pim_groupconf_node::RPRejLogIgnore },
	{ 0 }
};

enum {
	pim_intfconf_method_neighbor_acl = 1000,
};

static struct method_info pim_intfconf_methods[] = {
	{ "neighbor-acl", "Defines the neighbor access list",
	  pim_intfconf_method_neighbor_acl, false, 0 },
	{ 0 }
};

enum {
	pim_groupconf_method_rp_source_acl = 1000,
};

static struct method_info pim_groupconf_methods[] = {
	{ "rp-source-acl", "Defines the register source access list",
	  pim_groupconf_method_rp_source_acl, false, 0 },
	{ 0 }
};

bool pim_source_filter::accepts(const in6_addr &src) const {
	for (std::set<inet6_addr>::const_iterator i = sources.begin();
			i != sources.end(); ++i) {
		if (i->matches(src)) {
			return !filter_mode;
		}
	}

	/* no match */
	return filter_mode;
}

static bool _parse_filter(pim_source_filter &flt, const std::vector<std::string> &args) {
	if (args.empty())
		return false;
	if (args[0] != "accept" && args[0] != "reject")
		return false;
	bool new_filter = (args[0] == "reject");

	std::vector<std::string>::const_iterator i = args.begin();
	++i;

	std::set<inet6_addr> addrs;

	for (; i != args.end(); ++i) {
		inet6_addr addr;
		if (!addr.set(*i))
			return false;
		addrs.insert(addr);
	}

	flt.filter_mode = new_filter;
	flt.sources = addrs;

	/* XXX act? */

	return true;
}

pim_intfconf_node::pim_intfconf_node(intfconf *conf)
	: intfconf_node(conf, "pim") {
	neigh_acl.filter_mode = true;
}

bool pim_intfconf_node::check_startup() {
	if (!base::check_startup())
		return false;

	import_methods(pim_intfconf_methods);

	return true;
}

bool pim_intfconf_node::fill_defaults() {
	for (pim_property *p = pim_intf_props; p->name; p++)
		instantiate_property_u(p->name, p->value, p->description);

	instantiate_property_b("cisco-old-addrlist", false);

	return m_properties.size() == 15;
}

bool pim_intfconf_node::set_property(const char *key, const char *val) {
	if (!next_similiar_node()->has_property(key))
		return false;
	if (!strcmp(key, "cisco-old-addrlist"))
		return set_property_inst(key, property_def::VAL_BOOL, val);
	return set_property_inst(key, property_def::VAL_UNSIGNED, val);
}

bool pim_intfconf_node::call_method(int id, base_stream &out,
				    const std::vector<std::string> &args) {
	switch (id) {
	case pim_intfconf_method_neighbor_acl:
		return _parse_filter(neigh_acl, args);
	}

	return intfconf_node::call_method(id, out, args);
}

uint32_t pim_intfconf_node::hello_interval() const {
	return get_property_unsigned("hello-interval");
}

uint32_t pim_intfconf_node::holdtime() const {
	return (uint32_t)(hello_interval() * 3.5);
}

uint32_t pim_intfconf_node::joinprune_interval() const {
	return get_property_unsigned("joinprune-interval");
}

uint32_t pim_intfconf_node::joinprune_holdtime() const {
	return (uint32_t)(joinprune_interval() * 3.5);
}

uint32_t pim_intfconf_node::joinprune_supression_timeout() const {
	return (uint32_t)(joinprune_interval() * 1.25);
}

uint32_t pim_intfconf_node::data_timeout() const {
	return get_property_unsigned("data-timeout");
}

uint32_t pim_intfconf_node::register_supression_timeout() const {
	return get_property_unsigned("register-supression-timeout");
}

uint32_t pim_intfconf_node::probe_time() const {
	return get_property_unsigned("probe-time");
}

uint32_t pim_intfconf_node::assert_timeout() const {
	return get_property_unsigned("assert-timeout");
}

uint32_t pim_intfconf_node::random_delay_join_timeout() const {
	return get_property_unsigned("random-delay-join-timeout");
}

uint32_t pim_intfconf_node::dr_priority() const {
	return get_property_unsigned("dr-priority");
}

uint32_t pim_intfconf_node::register_stop_rate_limit() const {
	return get_property_unsigned("register-stop-rate-limit");
}

uint32_t pim_intfconf_node::register_stop_rate_timelen() const {
	return get_property_unsigned("register-stop-rate-timelen");
}

uint32_t pim_intfconf_node::propagation_delay() const {
	return get_property_unsigned("propagation-delay");
}

uint32_t pim_intfconf_node::override_interval() const {
	return get_property_unsigned("override-interval");
}

bool pim_intfconf_node::support_old_cisco_addrlist() const {
	return get_property_bool("cisco-old-addrlist");
}

bool pim_intfconf_node::neigh_acl_accepts(const in6_addr &src) const {
	return neigh_acl.accepts(src);
}

pim_groupconf_node::pim_groupconf_node(groupconf *conf)
	: groupconf_node(conf, "pim") {
}

bool pim_groupconf_node::check_startup() {
	if (!base::check_startup())
		return false;

	import_methods(pim_groupconf_methods);

	return true;
}

bool pim_groupconf_node::fill_defaults() {
	instantiate_property_a("rp", inet6_addr::any());
	instantiate_property_a("accept_rp", inet6_addr(in6addr_any, 0));
	instantiate_property_b("rp_adv", false);

	instantiate_property("rp-rejected-source-policy", new propval_enum(rp_rej_entries));

	instantiate_property_b("rp-embedded-auto-source-acl", false);

#if 0
	m_properties["use_spt"] = always_use;

	m_properties["rp_acl"] = rpa_any;
	m_properties["rp_acls"] = std::vector<inet6_addr>();

	std::vector<std::string> rp_pref;

	rp_pref.push_back("embedded");
	rp_pref.push_back("rp_set");
	rp_pref.push_back("static");

	m_properties["rp_pref"] = rp_pref;
#endif

	return m_properties.size() == 4;
}

bool pim_groupconf_node::set_property(const char *key, const char *value) {
	if (!strcmp(key, "rp")) {
		if (!strcmp(value, "none"))
			return set_property_inst("rp", property_def::VAL_ADDRESS, "::/128");
		else
			return set_property_inst("rp", property_def::VAL_ADDRESS, value);
	} else if (!strcmp(key, "accept_rp")) {
		if (!strcmp(value, "none")) {
			return set_property_inst("rp", property_def::VAL_ADDRESS, "::/128");
		} else if (strcmp(value, "embedded") == 0) {
			inet6_addr tmp;
			if (!pim_group_node::calculate_embedded_rp_addr(((groupconf *)parent())->id(), tmp)) {
				if (pim->should_log(WARNING)) {
					pim->log().writeline("Group doesn't follow Embedded-RP specification, "
							     "changing accept_rp to any.");
				}

				return false;
			}
			/* sigh */
			return set_property_inst("accept_rp", property_def::VAL_ADDRESS,
						 tmp.as_string().c_str());
		}
	} else if (!strcmp(key, "rp_adv")) {
#ifndef PIM_NO_BSR
		bool prev = get_property_bool("rp_adv");

		if (!set_property_inst("rp_adv", property_def::VAL_BOOL, value))
			return false;

		if (prev != get_property_bool("rp_adv"))
			pim->bsr().enable_rp_adv(((groupconf *)parent())->id(), !prev);

		return true;
#else
		return false;
#endif
	} else if (!strcmp(key, "rp-rejected-source-policy")) {
		if (!has_property("rp-rejected-source-policy")) {
			if (!instantiate_property("rp-rejected-source-policy",
						  new propval_enum(rp_rej_entries)))
				return false;
		}
	} else if (!strcmp(key, "rp-embedded-auto-source-acl")) {
		return set_property_inst("rp-embedded-auto-source-acl",
					 property_def::VAL_BOOL, value);
	}

	return groupconf_node::set_property(key, value);
}

bool pim_groupconf_node::call_method(int id, base_stream &out,
				    const std::vector<std::string> &args) {
	switch (id) {
	case pim_groupconf_method_rp_source_acl:
		return _parse_filter(rp_source_acl, args);
	}

	return groupconf_node::call_method(id, out, args);
}

bool pim_groupconf_node::increment_property(const char *key, const char *value) {
#if 0
	if (key == "rp_acls") {
		inet6_addr addr;
		if (addr.set(value)) {
			std::vector<inet6_addr> addrs = get_value("rp_acls")->as<std::vector<inet6_addr> >();
			addrs.push_back(addr);
			m_properties["rp_acls"] = addrs;
		} else {
			return false;
		}
	} else {
#endif
		return false;
#if 0
	}

	return true;
#endif
}

bool pim_groupconf_node::rp_for_group(const in6_addr &grpaddr, in6_addr &rpaddr,
				      rp_source &src) const {
	bool R_bit = grpaddr.s6_addr[1] & 0x40;
	bool P_bit = grpaddr.s6_addr[1] & 0x20;
	bool T_bit = grpaddr.s6_addr[1] & 0x10;

	if (P_bit && T_bit && R_bit) {
		/* Embedded-RP address */
		inet6_addr tmp;
		pim_group_node::calculate_embedded_rp_addr(grpaddr, tmp);
		rpaddr = tmp;
		src = rps_embedded;
		return true;
	}

	rpaddr = get_property_address("rp");
	if (!IN6_IS_ADDR_UNSPECIFIED(&rpaddr)) {
		src = rps_static;
		return true;
	}

#ifndef PIM_NO_BSR
	rpaddr = pim->bsr().rp_from_rpset(grpaddr);
	if (!IN6_IS_ADDR_UNSPECIFIED(&rpaddr)) {
		src = rps_rp_set;
		return true;
	}
#endif

	return false;
}



int pim_groupconf_node::rp_rejected_source_policy() const {
	return get_property_integer("rp-rejected-source-policy");
}

bool pim_groupconf_node::rp_source_acl_accepts(const pim_group_node *gn,
					       const in6_addr &src) const {
	if (gn->is_embedded()) {
		if (get_property_bool("rp-embedded-auto-source-acl")) {
			return gn->embedded_rp_addr().matches(src);
		}
	}

	return rp_source_acl.accepts(src);
}


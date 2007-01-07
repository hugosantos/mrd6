/*
 * Multicast Routing Daemon (MRD)
 *   mld_conf.cpp
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

#include <mrdpriv/mld/router.h>
#include <mrdpriv/mld/def.h>

#include <mrd/mrd.h>

enum {
	mld_intfconf_method_signaling_filter = 3000,
};

static const method_info mld_intfconf_node_methods[] = {
	{ "signaling-filter", 0, mld_intfconf_method_signaling_filter, false, 0 },
	{ 0 }
};

mld_intfconf_node::mld_intfconf_node(intfconf *conf)
	: intfconf_node(conf, "mld") {
}

bool mld_intfconf_node::check_startup() {
	if (!intfconf_node::check_startup())
		return false;

	import_methods(mld_intfconf_node_methods);

	return true;
}

bool mld_intfconf_node::fill_defaults() {
	instantiate_property_u("robustness", 2);
	instantiate_property_u("query_interval", 125000);
	instantiate_property_u("query_response_interval", 10000);
	instantiate_property_u("startup_query_interval", 125000 / 4);
	instantiate_property_u("startup_query_count", 2);
	instantiate_property_u("last_listener_query_interval", 1000);
	instantiate_property_u("last_listener_query_count", 2);
	instantiate_property_u("unsolicited_report_interval", 1000);
	instantiate_property_u("version", 2);

	instantiate_property_b("querier", true);

	instantiate_property("proxy_to", property_def::VAL_STRING);

	return m_properties.size() == 11;
}

bool mld_intfconf_node::call_method(int id, base_stream &out,
				   const std::vector<std::string> &args) {
	if (id == mld_intfconf_method_signaling_filter) {
		std::set<inet6_addr> filter;

		for (std::vector<std::string>::const_iterator i =
				args.begin(); i != args.end(); ++i) {
			inet6_addr addr;
			if (!addr.set(i->c_str()))
				return false;
			filter.insert(filter.end(), addr);
		}

		m_signaling_filter = filter;

		return true;
	}

	return intfconf_node::call_method(id, out, args);
}

bool mld_intfconf_node::set_property(const char *key, const char *value) {
	if (!next_similiar_node()->has_property(key))
		return false;

	return set_property_inst(key, property_def::VAL_UNSIGNED, value);
}

uint32_t mld_intfconf_node::robustness() const {
	return get_property_unsigned("robustness");
}

uint32_t mld_intfconf_node::query_interval() const {
	return get_property_unsigned("query_interval");
}

uint32_t mld_intfconf_node::query_response_interval() const {
	return get_property_unsigned("query_response_interval");
}

uint32_t mld_intfconf_node::mali() const {
	return robustness() * query_interval() + query_response_interval();
}

uint32_t mld_intfconf_node::other_querier_present_timeout() const {
	return robustness() * query_interval() + query_response_interval() / 2;
}

uint32_t mld_intfconf_node::startup_query_interval() const {
	return get_property_unsigned("startup_query_interval");
}

uint32_t mld_intfconf_node::startup_query_count() const {
	return get_property_unsigned("startup_query_count");
}

uint32_t mld_intfconf_node::last_listener_query_interval() const {
	return get_property_unsigned("last_listener_query_interval");
}

uint32_t mld_intfconf_node::last_listener_query_count() const {
	return get_property_unsigned("last_listener_query_count");
}

uint32_t mld_intfconf_node::last_listener_query_time() const {
	return last_listener_query_interval() * last_listener_query_count();
}

uint32_t mld_intfconf_node::unsolicited_report_interval() const {
	return get_property_unsigned("unsolicited_report_interval");
}

uint32_t mld_intfconf_node::older_version_querier_present_timeout() const {
	/* XXX query_interval should be the last query_interval received */
	return robustness() * query_interval() + query_response_interval();
}

uint32_t mld_intfconf_node::version() const {
	return get_property_unsigned("version");
}

bool mld_intfconf_node::querier() const {
	return get_property_bool("querier");
}

const std::set<inet6_addr> &mld_intfconf_node::signaling_filter() const {
	return m_signaling_filter;
}

mld_groupconf_node::mld_groupconf_node(groupconf *parent)
	: groupconf_node(parent, "mld") {
}

bool mld_groupconf_node::fill_defaults() {
	if (!instantiate_property_b("forward", false))
		return false;
	return true;
}

bool mld_groupconf_node::set_property(const char *key, const char *value) {
	return !strcmp(key, "forward") && set_property_inst(key, property_def::VAL_BOOL, value);
}


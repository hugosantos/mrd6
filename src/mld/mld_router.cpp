/*
 * Multicast Routing Daemon (MRD)
 *   mld_router.cpp
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
#include <mrd/address.h>
#include <mrd/interface.h>
#include <mrd/group.h>

#include <errno.h>
#include <cstring>
#include <cmath>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#ifndef IP6_ALERT_MLD
#define IP6_ALERT_MLD 0x00
#endif

mld_router *mld = 0;

in6_addr in6addr_linkscope_allnodes;

enum {
	mld_router_method_show_groups = 9500,
};

static const method_info mld_router_methods[] = {
	{ "groups", "Display MLD membership information",
		mld_router_method_show_groups, true, 0 },
	{ 0 }
};

enum {
	QueryCount = 0,
	ReportCount,
	ReductionCount,
	ReportV2Count,
	MessageCount
};

enum {
	RX = 0,
	TX,
	Bad
};

static const char *stats_descriptions[] = {
	"Query",
	"Report",
	"Reduction",
	"Report (V2)",
};

mld_interface::mld_interface()
	: interface_node(mld),
	  mif_query_timer_id("mld query", this,
		std::mem_fun(&mld_interface::handle_send_query_timeout)),
	  mif_other_querier_present_timer_id("other mld querier present", this,
		std::mem_fun(&mld_interface::handle_other_querier_present_timeout)),
	  m_stats(this, MessageCount, stats_descriptions) {

	mif_isquerier = true;

	mif_mld_version = 2;

	mif_query_count = 0;
}

mld_interface::~mld_interface() {
}

void mld_interface::attached(interface *node) {
	interface_node::attached(node);

	mif_isquerier = conf()->querier();
	mif_mld_version = conf()->version();

	std::string tmrname;

	tmrname = "mld query (";
	tmrname += owner()->name();
	tmrname += ")";

	mif_query_timer_id.name = tmrname;

	tmrname = "other mld querier present (";
	tmrname += owner()->name();
	tmrname += ")";

	mif_other_querier_present_timer_id.name = tmrname;

	mif_query_timer_id.update(conf()->query_interval(), true);

	mif_other_querier_present_timer_id.update(
			conf()->other_querier_present_timeout(), false);
}

bool mld_interface::check_startup() {
	if (!m_stats.setup("MLD Statistics"))
		return false;

	m_stats.disable_counter(ReportCount, TX);
	m_stats.disable_counter(ReductionCount, TX);
	m_stats.disable_counter(ReportV2Count, TX);

	return interface_node::check_startup();
}

bool mld_interface::output_info(base_stream &ctx, const std::vector<std::string> &) const {
	ctx.xprintf("MLD, version %i", (int)mif_mld_version);

	if (owner()->linklocals().empty()) {
		ctx.writeline(", not running");
		return true;
	}

	ctx.newl();

	ctx.inc_level();

	if (!mif_isquerier) {
		if (mif_querier_addr.is_any()) {
			ctx.writeline("Querier: None");
		} else {
			ctx.xprintf("Querier: %{Addr} for %{duration}\n",
				    mif_querier_addr,
				    mif_other_querier_present_timer_id.time_left_d());
		}
	} else {
		ctx.writeline("Querier: self");
	}

	ctx.dec_level();

	return true;
}

void mld_interface::address_added_or_removed(bool added, const inet6_addr &addr) {
	if (added) {
		if (addr.is_linklocal()) {
			mif_query_count = 0;

			if (mif_isquerier) {
				start_querying();
			}
		}
	} else {
		if (addr.is_linklocal()) {
			// XXX
			// clear interface references from group etc
			// stop timers and reset
		}
	}
}

void mld_interface::start_querying() {
	if (conf()->startup_query_count() <= 1) {
		mif_query_timer_id.update(conf()->query_interval(), true);

		mif_query_count = 0xffffffff;
	} else {
		mif_query_timer_id.update(conf()->startup_query_interval(), true);

		mif_query_count = 1;
	}

	mif_query_timer_id.start();

	send_mld_query(in6addr_any);
}

void mld_interface::shutdown() {
	owner()->dettach_node(this);

	mif_query_timer_id.stop();
	mif_other_querier_present_timer_id.stop();
}

static inline bool _is_mld_message(int code) {
	switch (code) {
	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:
	case MLD_LISTENER_REDUCTION:
	case MLDv2_LISTENER_REPORT:
	case MLDv2_LISTENER_REPORT_OLD:
		return true;
	default:
		return false;
	}
}

static inline const char *_mld_message_name(int code) {
	switch (code) {
	case MLD_LISTENER_REPORT:
		return "MLDv1 Membership Report";
	case MLD_LISTENER_REDUCTION:
		return "MLDv1 Membership Reduction";
	case MLD_LISTENER_QUERY:
		return "MLD Membership Query";
	case MLDv2_LISTENER_REPORT:
		return "MLDv2 Membership Report";
	case MLDv2_LISTENER_REPORT_OLD:
		return "MLDv2 Membership Report (old)";
	default:
		return "Unknown";
	}
}

void mld_interface::message_available(const in6_addr &from, const in6_addr &to,
				      icmp6_hdr *icmphdr, int len) {
	if (should_log(MESSAGE_SIG)) {
		log().xprintf("Received a %s from %{addr} to %{addr}\n",
			      _mld_message_name(icmphdr->icmp6_type),
			      from, to);
	}

	switch (icmphdr->icmp6_type) {
	case MLD_LISTENER_REPORT:
		handle_mldv1_membership_report(from, (mldv1 *)icmphdr);
		break;
	case MLD_LISTENER_REDUCTION:
		handle_mldv1_membership_reduction(from, (mldv1 *)icmphdr);
		break;
	case MLD_LISTENER_QUERY:
		handle_membership_query(from);
		break;
	case MLDv2_LISTENER_REPORT:
	case MLDv2_LISTENER_REPORT_OLD:
		handle_mldv2_membership_report(from, (mldv2_report *)icmphdr, len);
		break;
	}
}

void mld_interface::icmp_message_available(const in6_addr &from, const in6_addr &to,
					   icmp6_hdr *icmphdr, int len) {
	if (!_is_mld_message(icmphdr->icmp6_type)) {
		return;
	}

	if (conf()->has_property("proxy_to")) {
		const char *newintfname = conf()->get_property_string("proxy_to");

		interface *newintf = g_mrd->get_interface_by_name(newintfname);

		if (newintf) {
			mld_interface *newmldintf = mld->get_interface(newintf->index());
			if (newmldintf) {
				if (newmldintf == this) {
					if (should_log(DEBUG))
						log().writeline("Trying to proxy to same interface?");
				} else {
					newmldintf->message_available(from, to, icmphdr, len);
					return;
				}
			}
		}

		if (should_log(DEBUG)) {
			log().xprintf("Tried to redirect MLD signaling to %s"
				      "but failed. Signaling is being dropped.\n",
				      newintfname);
		}

		return;
	}

	message_available(from, to, icmphdr, len);
}

bool mld_interface::send_mld_query(const in6_addr &addr) {
	if (should_log(MESSAGE_SIG)) {
		if (IN6_IS_ADDR_UNSPECIFIED(&addr)) {
			log().writeline("Sending General Query");
		} else {
			log().xprintf("Sending Multicast Group Address "
				      "specific Query for %{addr}\n", addr);
		}
	}

	bool res;

	if (mif_mld_version >= 2) {
		res = send_mldv2_query(addr);
	} else {
		res = send_mldv1_query(addr);
	}

	if (res) {
		m_stats.counter(QueryCount, TX)++;
		mld->stats().counter(QueryCount, TX)++;
	} else {
		/*m_stats.counter(FailedSendQueryCount)++;
		mld->stats().counter(FailedSendQueryCount)++;*/
	}

	return res;
}

bool mld_interface::send_mldv2_query(const in6_addr &addr) {
	mldv2_query query;
	query.construct_query(addr, conf());
	return mld->send_icmp(owner(), in6addr_linkscope_allnodes,
			      (icmp6_hdr *)&query, query.length());
}

bool mld_interface::send_mldv1_query(const in6_addr &addr) {
	mldv1_query q;
	q.construct(addr, conf());
	return mld->send_icmp(owner(), in6addr_linkscope_allnodes,
			      (icmp6_hdr *)&q, q.length());
}

bool mld_interface::send_mld_query(const in6_addr &addr, const std::set<in6_addr> &sources) {
	if (!sources.empty() && mif_mld_version >= 2) {
		mldv2_query *query = g_mrd->opktb->header<mldv2_query>();

		query->construct_query(addr, conf());

		query->nsrcs = hton((uint16_t)sources.size());

		in6_addr *addr = g_mrd->opktb->header<in6_addr>(sizeof(mldv2_query));

		for (std::set<in6_addr>::const_iterator i = sources.begin();
				i != sources.end(); ++i) {
			*addr = *i;
			addr++;
		}

		if (mld->send_icmp(owner(), in6addr_linkscope_allnodes,
				   (icmp6_hdr *)query, query->length())) {
			m_stats.counter(QueryCount, TX)++;
			mld->stats().counter(QueryCount, TX)++;
			return true;
		} else {
			/*m_stats.counter(FailedSendQueryCount)++;
			mld->stats().counter(FailedSendQueryCount)++;*/
			return false;
		}
	}

	return true;
}

struct create_group_mld_context : mrd::create_group_context {
	int mld_mode;
	address_set mld_sources;
};

void mld_interface::handle_mode_change_for_group(int ver, const inet6_addr &reqsrc,
		const inet6_addr &grpaddr, int mode, const address_set &srcs) {
	const std::set<inet6_addr> &signaling_filter = conf()->signaling_filter();

	if (!signaling_filter.empty()) {
		bool accept = false;

		for (std::set<inet6_addr>::const_iterator i = signaling_filter.begin();
				!accept && i != signaling_filter.end(); ++i) {
			accept = i->matches(grpaddr);
		}

		if (!accept) {
			if (should_log(DEBUG)) {
				log().xprintf("Rejected mode change for group "
					      "%{Addr} by filter.\n", grpaddr);
			}

			return;
		}
	}

	if (((mode == MLD_SSM_MODE_INCLUDE || mode == MLD_SSM_CHANGE_TO_INCLUDE) && srcs.empty())
		|| (mode == MLD_SSM_ALLOW_SOURCES || mode == MLD_SSM_BLOCK_SOURCES)) {
		/* if mode for this record is Include {}, TO_IN {}, ALLOW {A} or BLOCK {A}
		 * dont create group if it doesnt exist */
		group *grp = g_mrd->get_group_by_addr(grpaddr);
		if (grp) {
			mld_group_interface *oif = mld->match(grp)->local_oif(this);
			if (oif)
				oif->refresh(reqsrc, mode, srcs);
		}

		return;
	}

	create_group_mld_context *ctx = new create_group_mld_context;
	if (!ctx)
		return;

	ctx->iif = owner()->index();
	ctx->groupaddr = grpaddr;
	ctx->requester = reqsrc;

	ctx->mld_mode = mode;
	ctx->mld_sources = srcs;

	g_mrd->create_group(mld, this, ctx);
}

void mld_interface::event(int event, void *ptr) {
	if (event != mrd::CreatedGroup) {
		interface_node::event(event, ptr);
		return;
	}

	create_group_mld_context *ctx = (create_group_mld_context *)ptr;

	if (ctx->result) {
		mld_group_interface *oif = mld->match(ctx->result)->local_oif(this);
		if (oif)
			oif->refresh(ctx->requester, ctx->mld_mode, ctx->mld_sources);
	} else {
		if (mld->should_log(VERBOSE)) {
			mld->log().xprintf("Creation of group %{Addr}"
				   " was denied for %{Addr}\n", ctx->groupaddr,
				   ctx->requester);
		}
	}

	delete ctx;
}

void mld_interface::handle_mldv1_membership_report(const in6_addr &src,
						   mldv1 *mldhdr) {
	m_stats.counter(ReportCount, RX)++;
	mld->stats().counter(ReportCount, RX)++;

	if (!IN6_IS_ADDR_MULTICAST(&mldhdr->mcaddr)) {
		m_stats.counter(ReportCount, Bad)++;
		mld->stats().counter(ReportCount, Bad)++;
		return;
	}

	if (IN6_IS_ADDR_MC_NODELOCAL(&mldhdr->mcaddr)
	    || IN6_IS_ADDR_MC_LINKLOCAL(&mldhdr->mcaddr))
		return;

	handle_mode_change_for_group(1, src, mldhdr->mcaddr,
				     MLD_SSM_MODE_EXCLUDE, address_set());
}

void mld_interface::handle_mldv2_membership_report(const in6_addr &src,
						   mldv2_report *mldhdr,
						   int len) {
	m_stats.counter(ReportV2Count, RX)++;
	mld->stats().counter(ReportV2Count, RX)++;

	mldv2_mrec *mrec = mldhdr->mrecs();
	int clen = 0;

	int reccount = ntoh(mldhdr->nmrecs());

	for (int i = 0; i < reccount && clen < len; i++, mrec = mrec->next()) {
		clen += sizeof(mldv2_mrec);
		if (clen <= len)
			clen += sizeof(in6_addr) * ntoh(mrec->nsrcs);
	}

	if (clen > len) {
		if (should_log(MESSAGE_ERR))
			log().writeline("Dropped badly formed MLDv2 Membership");

		m_stats.counter(ReportV2Count, Bad)++;
		mld->stats().counter(ReportV2Count, Bad)++;
		return;
	}

	mrec = mldhdr->mrecs();
	for (int i = 0; i < reccount; i++, mrec = mrec->next()) {
		if (!IN6_IS_ADDR_MULTICAST(&mrec->mca) ||
		     IN6_IS_ADDR_MC_NODELOCAL(&mrec->mca) ||
		     IN6_IS_ADDR_MC_LINKLOCAL(&mrec->mca))
			continue;

		address_set sources;
		in6_addr *srcs = mrec->sources();
		for (uint16_t j = 0; j < ntoh(mrec->nsrcs); j++)
			sources += srcs[j];

		handle_mode_change_for_group(2, src, mrec->mca, mrec->type, sources);
	}
}

void mld_interface::handle_mldv1_membership_reduction(const in6_addr &src,
						      mldv1 *mldhdr) {
	m_stats.counter(ReductionCount, RX)++;
	mld->stats().counter(ReductionCount, RX)++;

	if (!IN6_IS_ADDR_MULTICAST(&mldhdr->mcaddr)) {
		m_stats.counter(ReductionCount, Bad)++;
		mld->stats().counter(ReductionCount, Bad)++;
		return;
	}

	if (IN6_IS_ADDR_MC_NODELOCAL(&mldhdr->mcaddr)
	    || IN6_IS_ADDR_MC_LINKLOCAL(&mldhdr->mcaddr))
		return;

	handle_mode_change_for_group(1, src, mldhdr->mcaddr,
				     MLD_SSM_CHANGE_TO_INCLUDE, address_set());
}

void mld_interface::handle_membership_query(const in6_addr &src) {
	m_stats.counter(QueryCount, RX)++;
	mld->stats().counter(QueryCount, RX)++;

	// there should only be a MLD querier in a subnet network
	// so, if we are currently a querier, let's check if we have priority
	if (mif_isquerier) {
		if (src < *owner()->linklocal()) {
			change_is_querier(false);

			mif_querier_addr = src;

			if (should_log(NORMAL)) {
				log().xprintf("No longer the MLD querier in "
					      "this interface. Querier is at "
					      "%{Addr}\n", mif_querier_addr);
			}
		}
	} else {
		if (mif_querier_addr.is_any() || src < mif_querier_addr) {
			mif_querier_addr = src;

			if (should_log(NORMAL)) {
				log().xprintf("Querier is now at %{Addr}\n",
					      mif_querier_addr);
			}
		}
	}

	if (!mif_isquerier)
		mif_other_querier_present_timer_id.restart();
}

void mld_interface::change_is_querier(bool is) {
	if (mif_isquerier == is)
		return;

	mif_isquerier = is;

	if (mif_isquerier)
		start_querying();
	else
		mif_query_timer_id.stop();
}

void mld_interface::handle_other_querier_present_timeout() {
	change_is_querier(conf()->querier());

	if (!mif_isquerier)
		mif_querier_addr = inet6_addr();

	if (should_log(NORMAL)) {
		base_stream &os = log().write("The other querier timed out");
		if (mif_isquerier)
			os.write(", switching to Querier mode.");
		os.newl();
	}
}

void mld_interface::handle_send_query_timeout() {
	/* assert(mif_isquerier) */

	if (mif_isquerier) {
		send_mld_query(in6addr_any);

		if (mif_query_count != 0xffffffff) {
			mif_query_count ++;
			if (mif_query_count == conf()->startup_query_count()) {
				mif_query_timer_id.update(conf()->query_interval(), true);
				mif_query_count = 0xffffffff;
			}
		}
	}
}

///
///
///

mld_group_interface::mld_group_interface(mld_group *grp, mld_interface *intf)
	: group_interface(grp->owner(), grp, intf->owner()),
	  g_filter_timer("filter mode timer", this,
			  std::mem_fun(&mld_group_interface::handle_filter_timer)),
	  g_last_listener_timer("last listener timer", this,
			  std::mem_fun(&mld_group_interface::handle_last_listener_query)) {
	g_owner = grp;
	g_intf = intf;
	g_creation_time = tval::now();

	g_last_listener_query_count = 0;
}

mld_group_interface::~mld_group_interface() {
	g_sources_timers.clear();
}

uint32_t mld_group_interface::mali() const {
	return g_intf->conf()->mali();
}

void mld_group_interface::output_info(base_stream &ctx, bool detailed) const {
	ctx.xprintf("Group-Interface %s [MLD]\n", intf()->name());

	ctx.inc_level();

	int maxsources = 3;
	const address_set &srcs = active_set();

	if (detailed) {
		maxsources = srcs.size();
	}

	ctx.xprintf("Filter: %s ", filter_mode() == include ? "Include" : "Exclude");

	if (srcs.empty()) {
		ctx.write("{}");
	} else {
		ctx.write("{");

		address_set::const_iterator i = srcs.begin();
		ctx.xprintf("%{addr}", *i);
		++i;

		for (int k = 1; k < maxsources && i != srcs.end(); ++i) {
			ctx.xprintf(", %{addr}", *i);
			k++;
		}

		if (i != srcs.end())
			ctx.write(", ...");

		ctx.write(" }");
	}

	if (g_filter_timer.is_running()) {
		ctx.xprintf(" (Reset in %{duration})", g_filter_timer.time_left_d());
	}

	ctx.newl();

	if (detailed) {
		if (!g_sources_timers.empty()) {
			ctx.writeline("Sources:");

			ctx.inc_level();

			std::vector<source_timer>::const_iterator i;

			for (i = g_sources_timers.begin();
					i != g_sources_timers.end(); ++i) {
				ctx.xprintf("%{addr} for %{duration}",
					    i->argument(), i->time_left_d());
			}

			ctx.dec_level();
		}
	}

	output_inner_info(ctx, detailed);

	ctx.dec_level();
}

void mld_group_interface::output_inner_info(base_stream &ctx, bool detailed) const {
}

static const char *_mode_name(int mode) {
	switch (mode) {
	case MLD_SSM_CHANGE_TO_INCLUDE:
		return "CHANGE_TO_INCLUDE";
	case MLD_SSM_ALLOW_SOURCES:
		return "ALLOW_SOURCES";
	case MLD_SSM_MODE_INCLUDE:
		return "MODE_INCLUDE";
	case MLD_SSM_CHANGE_TO_EXCLUDE:
		return "CHANGE_TO_EXCLUDE";
	case MLD_SSM_MODE_EXCLUDE:
		return "MODE_EXCLUDE";
	case MLD_SSM_BLOCK_SOURCES:
		return "BLOCK_SOURCES";
	default:
		return "UNKNOWN";
	}
}

void mld_group_interface::send_mld_query(bool general, const address_set &srcs) {
	if (general)
		g_intf->send_mld_query(owner()->id());
	else if (!general && !srcs.empty())
		g_intf->send_mld_query(owner()->id(), srcs);
}

void mld_group_interface::refresh(const inet6_addr &src, int mode,
				  const address_set &sources) {
	if (g_last_listener_timer.is_running()
		&& !((mode == MLD_SSM_CHANGE_TO_INCLUDE
		    || mode == MLD_SSM_MODE_INCLUDE) && sources.empty())) {
		/* Cancel fast-leave */
		g_last_listener_timer.stop();
	}

	g_last_reporter = src;

	if (should_log(MESSAGE_SIG)) {
		log().xprintf("Refresh triggered by %{Addr} with mode"
			      " %s and sources %{addrset}.\n", src,
			      _mode_name(mode), sources);
	}

	address_set diff;

	switch (g_filter_mode) {
	case include:
		switch (mode) {
		case MLD_SSM_CHANGE_TO_INCLUDE:
			/* Router State: INCLUDE(A)
			 * Report Received: TO_IN(B)
			 * New Router State: INCLUDE(A+B)
			 * Actions: (B)=MALI, Send Q(MA,A-B) */

			/* Send Q(MA,A-B) */
			send_mld_query(false, g_include_set - sources);

			/* the rest is processed below */

		case MLD_SSM_ALLOW_SOURCES:
		case MLD_SSM_MODE_INCLUDE:
			/* Router State: INCLUDE(A)
			 * Report Received: ALLOW(B), INCLUDE(B)
			 * New Router State: INCLUDE(A+B)
			 * Actions: (B)=MALI */

			/* A = A+B */
			g_include_set.union_with(sources, diff);
			/* (B)=MALI */
			update_sources_timer(sources);

			if (!diff.empty()) {
				dump_filter();
				owner()->trigger_mode_event(this, added_sources, diff);
			}
			break;

		case MLD_SSM_CHANGE_TO_EXCLUDE:
			/* Router State: INCLUDE(A)
			 * Report Received: TO_EX(B)
			 * New Router State: EXCLUDE(A*B,B-A)
			 * Actions: (B-A)=0, Delete (A-B), Send Q(MA,A*B), Filter Timer=MALI */

			/* Send Q(MA,A*B) */
			send_mld_query(false, g_include_set * sources);

			/* the rest is processed below */

		case MLD_SSM_MODE_EXCLUDE:
			/* Router State: INCLUDE(A)
			 * Report Received: EXCLUDE(B)
			 * New Router State: EXCLUDE(A*B,B-A)
			 * Actions: (B-A)=0, Delete (A-B), Filter Timer=MALI */

			g_filter_mode = exclude;

			/* X = A*B */
			g_request_set = g_include_set * sources;
			/* Y = B-A */
			g_exclude_set = sources - g_include_set;

			/* Delete (A-B) */
			delete_sources(g_include_set - sources);

			/* Filter Timer=MALI */
			restart_filter_timer();

			dump_filter();

			owner()->trigger_mode_event(this, all_sources, address_set());
			break;

		case MLD_SSM_BLOCK_SOURCES:
			/* Router State: INCLUDE(A)
			 * Report Received: BLOCK(B)
			 * New Router State: INCLUDE(A)
			 * Actions: Send Q(MA,A*B) */

			/* Fast leave */
			update_sources_timer(sources, g_intf->conf()->last_listener_query_interval() + 500);
			send_mld_query(false, sources);

			/* Send Q(MA,A*B) */
			send_mld_query(false, g_include_set * sources);
			break;
		}
		break;
	case exclude:
		switch (mode) {
		case MLD_SSM_CHANGE_TO_INCLUDE:
			/* Router State: EXCLUDE(X,Y)
			 * Report Received: TO_IN(A)
			 * New Router State: EXCLUDE(X+A,Y-A)
			 * Actions: (A)=MALI, Send Q(MA,X-A), Send Q(MA) */

			/* Send Q(MA,X-A) */
			send_mld_query(false, g_request_set - sources);
			/* Send Q(MA) */
			send_mld_query(true);

			start_fast_leave();

		case MLD_SSM_MODE_INCLUDE:
			/* Router State: EXCLUDE(X,Y)
			 * Report Received: INCLUDE(A)
			 * New Router State: EXCLUDE(X+A,Y-A)
			 * Actions: (A)=MALI */

			/* X = X+A */
			g_request_set.union_with(sources);
			/* Y = Y-A */
			g_exclude_set.diff_with(sources, diff);

			/* (A)=MALI */
			update_sources_timer(sources);

			if (!diff.empty()) {
				dump_filter();
				owner()->trigger_mode_event(this, removed_sources, diff);
			}

			break;

		case MLD_SSM_CHANGE_TO_EXCLUDE:
			/* Router State: EXCLUDE(X,Y)
			 * Report Received: TO_EX(A)
			 * New Router State: EXCLUDE(A-Y,Y*A)
			 * Actions: (A-X-Y)= Filter Timer, Delete (X-A), Delete (Y-A)
			 *	Send Q(MA,A-Y), Filter Timer=MALI */

			/* Send Q(MA,A-Y) */
			send_mld_query(false, sources - g_exclude_set);

		case MLD_SSM_MODE_EXCLUDE:
			/* Router State: EXCLUDE(X,Y)
			 * Report Received: EXCLUDE(A)
			 * New Router State: EXCLUDE(A-Y,Y*A)
			 * Actions: (A-X-Y)=Filter Timer, Delete (X-A), Delete (Y-A)
			 *	Filter Timer=MALI */

			/* (A-X-Y)=Filter Timer */
			update_sources_timer(sources - g_request_set - g_exclude_set,
						g_filter_timer.time_left());

			/* Delete (X-A) */
			delete_sources(g_request_set - sources);
			/* Delete (Y-A) */
			delete_sources(g_exclude_set - sources);

			/* X = A-Y */
			g_request_set = sources - g_exclude_set;
			/* Y = Y*A */
			g_exclude_set.intersect_with(sources);

			/* Filter Timer=MALI */
			restart_filter_timer();
			break;

		case MLD_SSM_ALLOW_SOURCES:
			/* Router State: EXCLUDE(X,Y)
			 * Report Received: ALLOW(A)
			 * New Router State: EXCLUDE(X+A,Y-A)
			 * Actions: (A)=MALI */

			/* X = X+A */
			g_request_set.union_with(sources);
			/* Y = Y-A */
			g_exclude_set.diff_with(sources, diff);

			/* (A)=MALI */
			update_sources_timer(sources);

			if (!diff.empty()) {
				dump_filter();
				owner()->trigger_mode_event(this, added_sources, diff);
			}
			break;

		case MLD_SSM_BLOCK_SOURCES:
			/* Router State: EXCLUDE(X,Y)
			 * Report Received: BLOCK(A)
			 * New Router State: EXCLUDE(X+(A-Y),Y)
			 * Actions: (A-X-Y)=Filter Timer, Send Q(MA,A-Y) */

			/* (A-X-Y)=Filter Timer */
			update_sources_timer(sources - g_request_set - g_exclude_set,
						g_filter_timer.time_left());

			/* Send Q(MA,A-Y) */
			send_mld_query(false, sources - g_exclude_set);

			/* X = X+(A-Y) */
			g_request_set.union_with(sources - g_exclude_set);

			break;
		}
		break;
	}
}

void mld_group_interface::start_fast_leave() {
	/* Implement fast leave */
	if (g_last_listener_timer.is_running())
		return;

	/* We already sent a Q(MA) */
	g_last_listener_query_count = 1;

	g_last_listener_timer.start(g_intf->conf()->last_listener_query_time(), true);
}

void mld_group_interface::handle_last_listener_query() {
	if (g_last_listener_query_count
		== g_intf->conf()->last_listener_query_count()) {
		/* If we reach here, no one reported */

		g_last_listener_timer.stop();

		delete_sources(g_exclude_set);

		g_include_set.clear();
		g_request_set.clear();
		g_exclude_set.clear();

		g_filter_mode = include;

		dump_filter();

		owner()->trigger_mode_event(this, all_sources, address_set());

		owner()->someone_lost_interest();
	} else {
		/* Send Q(MA) */
		send_mld_query(true);

		g_last_listener_query_count ++;
	}
}

uint32_t mld_group_interface::time_left_to_expiry(bool withft) const {
	uint32_t val = withft ? g_filter_timer.time_left() : 0;

	if (!g_sources_timers.empty()) {
		std::vector<source_timer>::const_iterator i = g_sources_timers.begin();

		for (; i != g_sources_timers.end(); ++i) {
			val = std::max(val, i->time_left());
		}
	}

	return val;
}

void mld_group_interface::delete_sources(const address_set &sources) {
	bool changed = false;

	for (address_set::const_iterator i =
			sources.begin(); i != sources.end(); ++i) {
		for (std::vector<source_timer>::iterator k = g_sources_timers.begin();
						k != g_sources_timers.end(); ++k) {
			if (k->argument() == *i) {
				g_sources_timers.erase(k);

				if (g_include_set.has_addr(*i)) {
					g_include_set.remove(*i);
					if (g_filter_mode == include) {
						changed = true;
						owner()->trigger_mode_event(this, removed_sources, *i);

						if (g_include_set.empty()) {
							if (owner()->someone_lost_interest())
								return;
						}
					}
				} else if (g_request_set.has_addr(*i)) {
					g_request_set.remove(*i);
					g_exclude_set.insert(*i);
					changed = true;
					owner()->trigger_mode_event(this, added_sources, *i);
				} else if (g_exclude_set.has_addr(*i)) {
					g_exclude_set.remove(*i);
					changed = true;
					owner()->trigger_mode_event(this, removed_sources, *i);
				}

				break;
			}
		}
	}

	if (changed)
		dump_filter();
}

void mld_group_interface::update_sources_timer(const address_set &sources,
						uint32_t interval) {
	if (interval == 0)
		interval = mali();

	for (address_set::const_iterator i = sources.begin(); i != sources.end(); ++i) {
		std::vector<source_timer>::iterator k = g_sources_timers.begin();

		for (; k != g_sources_timers.end() && !(k->argument() == *i); ++k);

		if (k == g_sources_timers.end()) {
			std::string tmp;
			tmp = "mld source timer (";
			tmp += inet6_addr(*i).as_string();
			tmp += ")";

			k = g_sources_timers.insert(g_sources_timers.end(),
					source_timer(tmp, this,
					std::mem_fun(&mld_group_interface::handle_source_timeout), *i));
		}

		k->start_or_update(interval, false);
	}
}

void mld_group_interface::handle_source_timeout(in6_addr &addr) {
	delete_sources(addr);
}

void mld_group_interface::restart_filter_timer() {
	g_filter_timer.start_or_update(mali(), false);
}

void mld_group_interface::handle_filter_timer() {
	delete_sources(g_exclude_set);

	g_include_set = g_request_set;
	g_request_set.clear();
	g_exclude_set.clear();

	g_filter_mode = include;

	dump_filter();

	owner()->trigger_mode_event(this, all_sources, address_set());

	if (g_include_set.empty())
		owner()->someone_lost_interest();
}

///
///
///

mld_group::mld_group(router *rt)
	: group_node(rt) {
}

mld_group::~mld_group() {
}

bool mld_group::output_info(base_stream &ctx, const std::vector<std::string> &) const {
	/* No Info */
	return true;
}

void mld_group::attached(group *grp) {
	group_node::attached(grp);

	/*
	if (!owner()->get_conf()->create_child("mld")) {
		return;
	}

	m_conf = owner()->get_conf()->get_child("mld");

	if (m_conf->get_property_bool("forward")) {
		m_mfa_inst = mld->mfa()->create_group(g_owner->id());
		if (m_mfa_inst) {
			m_mfa_wildcard = m_mfa_inst->create_source_state(inet6_addr::any());
		}
	}*/
}

void mld_group::dettached() {
	group_node::dettached();
}

void mld_group::subscriptions_changed(const group_interface *gintf,
		group_interface::event_type event, const address_set &sources) {
}

group_interface *mld_group::instantiate_group_interface(interface *intf) {
	mld_interface *mldintf = mld->get_interface(intf->index());

	if (mldintf)
		return new mld_group_interface(this, mldintf);

	return 0;
}

bool mld_group::has_interest_in_group() const {
	std::map<int, group_interface *>::const_iterator j;

	for (j = owner()->interface_table().begin();
			j != owner()->interface_table().end(); ++j) {
		if (const_cast<const group_node *>(j->second->owner_node()) == this) {
			if (!(j->second->filter_mode() == group_interface::include
					&& j->second->include_set().empty())) {
				return true;
			}
		}
	}

	return false;
}

mld_group_interface *mld_group::local_oif(mld_interface *intf) {
	group_interface *gif = g_owner->local_oif(intf->owner());

	if (gif && gif->owner_node() == this)
		return static_cast<mld_group_interface *>(gif);

	return 0;
}

///
///
///

mld_router::mld_router()
	: router("mld"),
	  m_stats(this, MessageCount, stats_descriptions) {

	in6addr_linkscope_allnodes = inet6_addr("ff02::1").address();
}

mld_router::~mld_router() {
}

const char *mld_router::description() const {
	return "Multicast Listener Discovery (MLD) protocol";
}

bool mld_router::check_startup() {
	if (!m_stats.setup("MLD Statistics"))
		return false;

	m_stats.disable_counter(ReportCount, TX);
	m_stats.disable_counter(ReductionCount, TX);
	m_stats.disable_counter(ReportV2Count, TX);

	if (!router::check_startup())
		return false;

	import_methods(mld_router_methods);

	g_mrd->icmp().register_handler(MLD_LISTENER_REPORT, this);
	g_mrd->icmp().register_handler(MLD_LISTENER_REDUCTION, this);
	g_mrd->icmp().register_handler(MLD_LISTENER_QUERY, this);
	g_mrd->icmp().register_handler(MLDv2_LISTENER_REPORT, this);
	g_mrd->icmp().register_handler(MLDv2_LISTENER_REPORT_OLD, this);

	in6_addr all_routers;
	in6_addr mld_all_routers;

	all_routers = inet6_addr("ff02::2").address();
	mld_all_routers = inet6_addr("ff02::16").address();

	g_mrd->icmp().require_mgroup(all_routers, true);
	g_mrd->icmp().require_mgroup(mld_all_routers, true);

	return true;
}

void mld_router::shutdown() {
	const mrd::interface_list &intflist = g_mrd->intflist();

	for (mrd::interface_list::const_iterator i = intflist.begin();
						i != intflist.end(); ++i) {
		mld_interface *mldintf =
			(mld_interface *)i->second->node_owned_by(this);
		if (mldintf) {
			mldintf->shutdown();
			delete mldintf;
		}
	}

	g_mrd->icmp().register_handler(MLD_LISTENER_REPORT, 0);
	g_mrd->icmp().register_handler(MLD_LISTENER_REDUCTION, 0);
	g_mrd->icmp().register_handler(MLD_LISTENER_QUERY, 0);
	g_mrd->icmp().register_handler(MLDv2_LISTENER_REPORT, 0);
	g_mrd->icmp().register_handler(MLDv2_LISTENER_REPORT_OLD, 0);

	in6_addr all_routers;
	in6_addr mld_all_routers;

	all_routers = inet6_addr("ff02::2").address();
	mld_all_routers = inet6_addr("ff02::16").address();

	g_mrd->icmp().require_mgroup(all_routers, false);
	g_mrd->icmp().require_mgroup(mld_all_routers, false);

	router::shutdown();
}

void mld_router::icmp_message_available(interface *intf, const in6_addr &src,
					const in6_addr &dst, icmp6_hdr *hdr,
					int len) {
	if (IN6_IS_ADDR_MULTICAST(&dst)) {
		mld_interface *mintf = get_interface(intf->index());
		if (mintf) {
			mintf->icmp_message_available(src, dst, hdr, len);
		} else if (_is_mld_message(hdr->icmp6_type)
			   && should_log(MESSAGE_ERR)) {
			mld->log_router_desc(intf->log()).writeline(
				"Incoming MLD message discarded, "
				"interface disabled.");
		}
	}
}

void mld_router::add_interface(interface *intf) {
	if (!intf->conf()->create_child("mld"))
		return;

	mld_interface *mldif = new mld_interface();
	if (!mldif)
		return;

	if (!intf->attach_node(mldif)) {
		delete mldif;
		return;
	}

	if (!mldif->check_startup()) {
		intf->dettach_node(mldif);
		delete mldif;
	}
}

void mld_router::remove_interface(interface *intf) {
	mld_interface *mldintf = (mld_interface *)intf->node_owned_by(this);

	if (mldintf) {
		mldintf->shutdown();
		delete mldintf;
	}
}

void mld_router::created_group(group *grp) {
	mld_group *mldgrp = allocate_group();
	if (mldgrp) {
		if (!mldgrp->check_startup()
			|| !grp->attach_node(mldgrp))
			delete mldgrp;
	} else {
		/// XXX
	}
}

mld_group *mld_router::allocate_group() {
	return new mld_group(this);
}

void mld_router::released_group(group *grp) {
	mld_group *mldgrp = (mld_group *)grp->node_owned_by(this);
	if (mldgrp) {
		grp->dettach_node(mldgrp);
		// mldgrp->shutdown();
		delete mldgrp;
	}
}

bool mld_router::call_method(int id, base_stream &out,
			     const std::vector<std::string> &args) {
	if (id == mld_router_method_show_groups) {
		inet6_addr mask;

		if (args.size() == 1) {
			if (!mask.set(args[0].c_str()))
				return false;
		} else if (args.size() > 1) {
			return false;
		}

		mrd::group_list::const_iterator i = g_mrd->group_table().begin();

		for (; i != g_mrd->group_table().end(); ++i) {
			if (!mask.matches(i->first))
				continue;

			mld_group *grp =
				(mld_group *)i->second->node_owned_by(this);
			if (!grp)
				continue;

			group::group_intfs::const_iterator j;

			int count = 0;

			j = i->second->interface_table().begin();
			for (; j != i->second->interface_table().end(); ++j) {
				if (j->second->owner_node() == grp)
					count++;
			}

			if (!count)
				continue;

			out.xprintf("%{Addr}\n", i->first);

			out.inc_level();

			j = i->second->interface_table().begin();
			for (; j != i->second->interface_table().end(); ++j) {
				if (j->second->owner_node() == grp) {
					mld_group_interface *mldintf =
						(mld_group_interface *)j->second;

					out.write(mldintf->intf()->name()).write(": ");
					mldintf->dump_filter(out);
					out.xprintf(", Uptime: %{duration}",
						    time_duration(mldintf->uptime()));

					uint32_t val = mldintf->time_left_to_expiry(true);
					if (val > 0) {
						out.xprintf(", Time left: %{duration}",
							    time_duration(val));
					}

					out.xprintf(", Last reporter: %{Addr}\n",
						    mldintf->last_reporter());
				}
			}

			out.dec_level();
		}

		return true;
	}

	return router::call_method(id, out, args);
}

bool mld_router::output_info(base_stream &, const std::vector<std::string> &) const {
	return false;
}

intfconf_node *mld_router::create_interface_configuration(intfconf *conf) {
	return new mld_intfconf_node(conf);
}

groupconf_node *mld_router::create_group_configuration(groupconf *conf) {
	return new mld_groupconf_node(conf);
}

mld_interface *mld_router::get_interface(int index) const {
	interface *intf = g_mrd->get_interface_by_index(index);
	if (intf)
		return (mld_interface *)intf->node_owned_by(this);
	return 0;
}

mld_group *mld_router::match(group *grp) const {
	return (mld_group *)grp->node_owned_by(this);
}

bool mld_router::send_icmp(const interface *intf, const in6_addr &addr,
			   icmp6_hdr *hdr, uint16_t len) const {
	return g_mrd->icmp().send_icmp(intf, addr, IP6_ALERT_MLD, hdr, len);
}

base_stream &mld_router::log_router_desc(base_stream &os) const {
	return os.write("MLD, ");
}


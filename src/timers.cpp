/*
 * Multicast Routing Daemon (MRD)
 *   timers.cpp
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>

#include <mrd/mrd.h>
#include <mrd/timers.h>

#include <sys/signal.h>
#include <sys/times.h>
#include <unistd.h>
#include <errno.h>

#include <list>

tval tval::operator + (const tval &tv) const {
	tval n = *this;
	n += tv;
	return n;
}

int32_t tval::operator - (const tval &tv) const {
	return (v.tv_sec - tv.v.tv_sec) * 1000 + (v.tv_usec - tv.v.tv_usec) / 1000;
}

tval tval::diff(const tval &tv) const {
	tval n;

	// diff = this - tv
	// with this = 10:10 and tv = 9:0 -> 1:10
	// with this = 11:0 and tv 10:50 -> 0:50

	if (v.tv_usec >= tv.v.tv_usec) {
		n.v.tv_usec = v.tv_usec - tv.v.tv_usec;
		n.v.tv_sec = v.tv_sec - tv.v.tv_sec;
	} else {
		n.v.tv_usec = tv.v.tv_usec - v.tv_usec;
		n.v.tv_sec = v.tv_sec - (tv.v.tv_sec + 1);
	}

	return n;
}

base_stream &tval::print_to(base_stream &os) const {
	return os.xprintf("%u:%llu", (uint32_t)v.tv_sec, (uint64_t)v.tv_usec);
}

timer_base::timer_base(const timer_base &original)
	: name(original.name), _running(original._running), _repeat(original._repeat),
	  _interval(original._interval), _perturb(original._perturb) {
	if (_running) {
		g_mrd->timemgr()->clone_position(&original, this);
	}

	_extra = 0;
}

timer_base::~timer_base() {
	stop();
}

bool timer_base::start(bool immediatly) {
	return start(_interval, _repeat, immediatly);
}

bool timer_base::start(uint32_t interval, bool repeat, bool immediatly,
		       uint32_t perturb) {
	if (!_running) {
		_running = true;
		_repeat = repeat;
		_interval = interval;
		_perturb = perturb;

		g_mrd->timemgr()->start_timer(this);

		if (immediatly)
			callback();
	}

	return true;
}

bool timer_base::stop() {
	if (_running) {
		g_mrd->timemgr()->stop_timer(this);
		_running = false;
		return true;
	}

	return false;
}

void timer_base::update(uint32_t interval, bool repeat, uint32_t perturb) {
	g_mrd->timemgr()->update_timer(this, interval, repeat, perturb);
}

uint32_t timer_base::time_left() const {
	if (!is_running())
		return 0;
	return g_mrd->timemgr()->time_left(this) + _extra;
}

base_stream &timer_base::print_to(base_stream &os) const {
	os.xprintf("%s, ", name.c_str());

	if (is_running()) {
		os.xprintf("Running, %{duration}", time_left());
	} else {
		os.write("Stopped");
	}

	return os;
}

timermgr::timermgr() {
	/* POSIX love */
	clk_tck = sysconf(_SC_CLK_TCK);
}

timermgr::~timermgr() {
}

bool timermgr::check_startup() {
	return true;
}

void timermgr::shutdown() {
}

void timermgr::start_timer(timer_base *def) {
	start_timer(def, def->_interval, def->_perturb);
}

void timermgr::start_timer(timer_base *def, uint32_t interval, uint32_t perturb) {
	/*
	 * [begin, 5] [10] [end]
	 *
	 * Case 1, insert 2:
	 *   -> [begin, 2] [3] [10] [end]
	 * Case 2, insert 7:
	 *   -> [begin, 5] [2] [8] [end]
	 * Case 3, insert 20:
	 *   -> [begin, 5] [10] [5] [end]
	 */

	uint32_t accum = 0;

	if (perturb) {
		int32_t i = interval;
		i += (mrd::get_randu32() % (2 * perturb) - perturb);
		interval = std::max(i, 0);
	}

	tq_def::iterator i = tq.begin();

	/*
	 * Case 1:
	 *   accum = 0, i = [begin, 5]
	 * Case 2:
	 *   accum = 5, i = [10]
	 * Case 3:
	 *   accum = 15, i = [end]
	 */

	while (1) {
		if (i == tq.end() || (accum + (*i)->_target) >= interval)
			break;
		accum += (*i)->_target;
		++i;
	}

	def->_extra = 0;
	def->_target = interval - accum;

	/* Case {1, 2} */
	if (i != tq.end())
		(*i)->_target -= def->_target;

	if (tq.empty()) {
		tms tmp;
		lastclk = times(&tmp);
		taccum = 0;
	}

	tq.insert(i, def);
}

void timermgr::stop_timer(timer_base *def) {
	/*
	 * [begin, 2] [5] [10] [end]
	 *
	 * Remove [5]:
	 *  -> [begin, 2] [10->15] [end]
	 */

	for (tq_def::iterator i = tq.begin(); i != tq.end(); ++i) {
		if (*i == def) {
			tq_def::iterator j = i;
			++j;

			if (j != tq.end())
				(*j)->_target += (*i)->_target;

			tq.erase(i);

			return;
		}
	}
}

void timermgr::update_timer(timer_base *def, uint32_t value, bool repeat,
			    uint32_t perturb) {
	if (def) {
		/* uint32_t prev = def->_interval; */

		def->_interval = value;
		def->_repeat = repeat;
		def->_perturb = perturb;

		if (def->is_running()) {
			/* XXX `extra` needs thinking: two updates without being
			 * triggered meanwhile, must increment. but meanwhile
			 * must take into account in start_timer */
			/*if (value > prev && *tq.begin() != def) {
				def->_extra = value - prev;
			} else {*/
				stop_timer(def);
				start_timer(def);
			/*}*/
		}
	}
}

void timermgr::clone_position(const timer_base *def1, timer_base *def2) {
	for (tq_def::iterator i = tq.begin(); i != tq.end(); ++i) {
		if (*i == def1) {
			def2->_target = 0;
			def2->_extra = def1->_extra;

			++i;

			tq.insert(i, def2);

			return;
		}
	}
}

void timermgr::handle_timer_event() {
	assert(!tq.empty());

	while (!tq.empty()) {
		timer_base *h = *tq.begin();

		/* Not your time yet baby */
		if (h->_target > taccum)
			return;

		taccum -= h->_target;

		tq.erase(tq.begin());

		if (h->_extra > 0) {
			start_timer(h, h->_extra, 0);
		} else {
			if (h->_repeat) {
				start_timer(h);
			} else {
				h->_running = false;
			}

			h->callback();
		}
	}
}

void timermgr::update_taccum() {
	tms tmp;
	clock_t now = times(&tmp);
	uint32_t diff = ((now - lastclk) * 1000) / clk_tck;
	lastclk = now;

	taccum += diff;
}

bool timermgr::handle_event() {
	update_taccum();

	handle_timer_event();

	return false;
}

static void _extend(char *buf, int size, int &avail, const char *fmt, ...) {
	if (avail == 0)
		return;

	int ptr = size - avail;

	if (avail < size) {
		buf[ptr + 0] = ' ';
		buf[ptr + 1] = 0;
		avail--;
		ptr++;
	}

	va_list vl;
	va_start(vl, fmt);
	int w = vsnprintf(buf + ptr, avail, fmt, vl);
	va_end(vl);

	if ((avail - w) < 0)
		avail = 0;
	else
		avail -= w;
}

static char *_prettyprint(char *buf, int size, uint32_t interval) {
	int avail = size;

	if (interval == 0) {
		/* we need at least 2 bytes in buf */
		strcpy(buf, "0");
		return buf;
	}

	if (interval < 1000) {
		_extend(buf, size, avail, "%ims", interval);
	} else {
		if (interval % 1000) {
			interval = (interval / 1000) + 1;
		} else {
			interval /= 1000;
		}

		if (interval > 86400) {
			_extend(buf, size, avail, "%ud", interval / 86400);
			interval %= 86400;
		}

		if (interval > 3600) {
			_extend(buf, size, avail, "%uh", interval / 3600);
			interval %= 3600;
		}

		if (interval > 60) {
			_extend(buf, size, avail, "%um", interval / 60);
			interval %= 60;
		}

		if (interval)
			_extend(buf, size, avail, "%us", interval);
	}

	return buf;
}

static void _draw_sep(base_stream &ctx, int n) {
	char buf[64];

	buf[0] = '+';
	memset(buf + 1, '-', n+2);
	buf[n+3] = 0;

	ctx.xprintf("%s+--------------+------------+----------+\n", buf);
}

bool timermgr::output_info(base_stream &ctx, bool extended) const {
	size_t namelen = 20;

	for (tq_def::const_iterator i = tq.begin();
			namelen < 50 && i != tq.end(); ++i) {
		timer_base *h = *i;
		if (h->name.size() > namelen)
			namelen = h->name.size();
	}

	if (namelen > 50)
		namelen = 50;

	char fmt[64];
	snprintf(fmt, sizeof(fmt), "| %%%is | %%12s | %%10s | %%8s |", (int)namelen);

	_draw_sep(ctx, namelen);
	ctx.printf(fmt, "timer name", "time left", "interval", "repeat").newl();
	_draw_sep(ctx, namelen);

	char buf1[64], buf2[64];

	for (tq_def::const_iterator i = tq.begin(); i != tq.end(); ++i) {
		timer_base *h = *i;

		_prettyprint(buf1, sizeof(buf1), h->time_left());
		_prettyprint(buf2, sizeof(buf2), h->_interval);

		ctx.printf(fmt, h->name.c_str(), buf1, buf2,
			   h->_repeat ? "true" : "false").newl();
	}

	_draw_sep(ctx, namelen);

	return true;
}

bool timermgr::time_left(timeval &tv) {
	if (tq.empty())
		return false;

	update_taccum();

	timer_base *h = *tq.begin();

	if (taccum > h->_target) {
		taccum -= h->_target;
		h->_target = 0;
	} else {
		h->_target -= taccum;
		taccum = 0;
	}

	tv.tv_sec = h->_target / 1000;
	tv.tv_usec = (h->_target % 1000) * 1000;

	return true;
}

uint32_t timermgr::time_left(const timer_base *def) const {
	uint32_t ac = 0;

	for (tq_def::const_iterator i = tq.begin(); i != tq.end(); ++i) {
		ac += (*i)->_target;

		if (def == *i) {
			break;
		}
	}

	if (taccum > ac)
		return 0;
	return ac - taccum;
}

void stream_push_formated_type(base_stream &os, const time_duration &d) {
	char *p = os.req_buffer(64);
	_prettyprint(p, 64, d.value);
	os.commit_change(strlen(p));
}


/*
 * Multicast Routing Daemon (MRD)
 *   log.cpp
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

#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>

#include <mrd/mrd.h>
#include <mrd/log.h>
#include <mrd/address_set.h>

#include <arpa/inet.h>

#include <algorithm>

enum {
	log_method_attach = 1000
};

static const method_info log_methods[] = {
	{ "attach", "Attaches a new log instance",
		log_method_attach, false, property_def::NEGATE },
	{ 0 }
};

enum {
	_LOG_INFO = 1,
	_LOG_WARN = 2,
	_LOG_FATAL = 4
};

stream_flusher::~stream_flusher() {
}

base_stream::base_stream()
	: fl(0), level(0), dec(true) {
	ptr = 0;
	buffer[0] = 0;
	currfmt = 0;
}

base_stream::base_stream(stream_flusher *flusher)
	: fl(flusher), level(0), dec(true) {
	ptr = 0;
	buffer[0] = 0;
	currfmt = 0;
}

base_stream::~base_stream() {
}

void base_stream::inc_level() {
	level++;
}

void base_stream::dec_level() {
	level--;
}

static const char _whites[] = "                "; /* 16 spaces */

void base_stream::spaces(int count) {
	while (count > 0) {
		int c = std::min(count, 16);
		append_chunk(_whites, c);
		count -= c;
	}
}

void base_stream::append_chunk(const char *str) {
	if (dec)
		append_chunk(str, strlen(str));
}

base_stream &base_stream::printf(const char *fmt, ...) {
	if (dec) {
		va_list vl;
		va_start(vl, fmt);

		int k = vsnprintf(req_buffer(192), 192, fmt, vl);
		if (k > 192)
			k = 192;
		commit_change(k);

		va_end(vl);
	}

	return *this;
}

void base_stream::advance_format() {
	assert(currfmt != 0);

	const char *p = currfmt;

	while (1) {
		if (currfmt[0] == '\n') {
			if (currfmt > p)
				append_chunk(p, currfmt - p);
			newl();
			p = currfmt + 1;
		} else if (currfmt[0] == '%') {
			if (currfmt[1] == '%') {
				if (currfmt > p)
					append_chunk(p, currfmt - p);
				append_chunk("%", 1);
				currfmt++;
				p = currfmt + 1;
			} else {
				break;
			}
		} else if (currfmt[0] == '\0') {
			break;
		}

		currfmt++;
	}

	if (currfmt > p)
		append_chunk(p, currfmt - p);
}

base_stream &base_stream::newl() {
	if (dec && fl)
		fl->flushed(str(), true);
	clear();

	return *this;
}

void base_stream::perror(const char *str) {
	xprintf("%s: %s.\n", str, strerror(errno));
}

void base_stream::set_decision(bool b) {
	dec = b;
}

void base_stream::flush() {
	if (dec && fl)
		fl->flushed(str(), false);

	clear();
}

void base_stream::ident_start() {
	int l = level;
	if (l > 20)
		l = 20;

	memset(buffer, ' ', l * 2);

	ptr = l * 2;
}

void base_stream::append_chunk(const char *str, int len) {
	append_chunk(str, len, true);
}

void base_stream::append_chunk(const char *str, int len, bool first) {
	if (len <= 0)
		return;

	if (dec) {
		if (first && ptr == 0) {
			ident_start();
		}

		int x;

		if ((len + ptr) > (int)(sizeof(buffer)-1)) {
			x = sizeof(buffer) - ptr - 1;
		} else {
			x = len;
		}

		strncpy(buffer + ptr, str, x);
		/* if sizeof(char) = 1 byte..
		memcpy(buffer + ptr, str, x);*/

		ptr += x;

		buffer[ptr] = 0;

		if (x < len) {
			flush();

			append_chunk(str + x, len - x, false);
		}
	}
}

char *base_stream::req_buffer(int n) {
	return req_buffer(n, true);
}

char *base_stream::req_buffer(int n, bool first) {
	if (n > (int)(sizeof(buffer)-1))
		return 0;

	if (first && ptr == 0)
		ident_start();

	/* must flush */
	if ((n + ptr) > (int)(sizeof(buffer)-1)) {
		/* prevent loops */
		if (!first)
			return 0;

		flush();

		return req_buffer(n, false);
	}

	return buffer + ptr;
}

void base_stream::commit_change(int n) {
	ptr += n;
}

void base_stream::nprintf(int n, const char *fmt, ...) {
	va_list vl;
	va_start(vl, fmt);
	commit_change(vsnprintf(req_buffer(n), n, fmt, vl));
	va_end(vl);
}

void base_stream::clear() {
	ptr = 0;
	buffer[0] = 0;
}

const char *base_stream::str() const {
	return buffer;
}

log_node::log_node(log_base *parent, const char *name, int level)
	: node(parent, name) {
	infolevel = instantiate_property_i("infolevel", level);
}

bool log_node::check_startup() {
	return node::check_startup() && infolevel != 0;
}

void log_node::set_level(const char *l) {
	set_property("infolevel", l);
}

bool log_node::set_property(const char *name, const char *value) {
	if (!strcmp(name, "infolevel")) {
		int level;
		if (!parse_infolevel(value, level))
			return false;
		/* very stupid'ish */
		char buf[32];
		snprintf(buf, sizeof(buf), "%i", level);

		return node::set_property(name, buf);
	}

	return node::set_property(name, value);
}

bool log_node::will_log(int type, int level) const {
	return type != _LOG_INFO || level <= infolevel->get_integer();
}

syslog_log_node::syslog_log_node(log_base *parent, const char *name, int infolevel)
	: log_node(parent, name, infolevel) {
}

syslog_log_node::~syslog_log_node() {
	closelog();
}

bool syslog_log_node::check_startup() {
	if (!log_node::check_startup())
		return false;

	openlog("mrd", LOG_PID, LOG_DAEMON);

	return true;
}

static inline int type_as_syslog_priority(int t) {
	switch (t) {
	case _LOG_INFO:
		return LOG_INFO;
	case _LOG_WARN:
		return LOG_WARNING;
	case _LOG_FATAL:
		return LOG_CRIT;
	default:
		return LOG_ERR;
	}
}

void syslog_log_node::log(int type, int level, const char *msg, bool) {
	syslog(type_as_syslog_priority(type), "%s", msg);
}

tb_log_node::tb_log_node(log_base *parent, const char *name, int level)
	: log_node(parent, name, level) {}

const char *
tb_log_node::timestamp(char *buffer, size_t length) const
{
	timeval tv;
	gettimeofday(&tv, NULL);
	time_t nowt = tv.tv_sec;

	assert(length >= 1);

	buffer[0] = '[';
	size_t l = strftime(buffer + 1, length - 1, "%b %d %T", localtime(&nowt));
	assert((l + 1) <= length);
	snprintf(buffer + 1 + l, length - l - 1, ":%06u]", (uint32_t)tv.tv_usec);

	return buffer;
}

file_log_node::file_log_node(log_base *parent, const char *name, int level,
			     const char *filename, bool flush)
	: tb_log_node(parent, name, level) {

	_base_filename = filename;

	_fp = fopen(filename, "a");

	_flush = instantiate_property_b("flush", flush);
}

file_log_node::file_log_node(log_base *parent, const char *name, int level,
			     FILE *param)
	: tb_log_node(parent, name, level), _fp(param) {

	_flush = instantiate_property_b("flush", false);
}

file_log_node::~file_log_node() {
	if (_fp && _fp != stderr) {
		fclose(_fp);
		_fp = 0;
	}
}

bool file_log_node::check_startup() {
	if (!log_node::check_startup())
		return false;
	return _flush != 0 && _fp != 0;
}

void file_log_node::log(int type, int level, const char *msg, bool newline) {
	if (!_fp)
		return;

	char tmp[64];
	fputs(timestamp(tmp, sizeof(tmp)), _fp);
	fputc(' ', _fp);
	fputs(msg, _fp);

	if (newline)
		fputc('\n', _fp);

	if (newline && _flush->get_bool())
		fflush(_fp);
}

void file_log_node::event(int ev, void *ptr) {
	if (ev == log_base::ReloadEvent) {
		if (_fp != stderr) {
			fclose(_fp);
			_fp = fopen(_base_filename.c_str(), "a");
		}
	} else {
		tb_log_node::event(ev, ptr);
	}
}

static void _handle_log_reload(int) {
	log_base::instance().reload_logs();
}

log_base::log_base(node *parent)
	: node(parent, "log"), _base(this) {
	_force_stderr = false;
}

log_base::~log_base() {
	signal(SIGHUP, SIG_IGN);

	clear_childs();
}

void log_base::remove_child_node(node *n) {
	delete (log_node *)n;
}

const char *log_base::description() const {
	return "Logging facilities";
}

bool log_base::check_startup() {
	if (!node::check_startup())
		return false;

	signal(SIGHUP, _handle_log_reload);

	import_methods(log_methods);

	return true;
}

void log_base::reload_logs() {
	broadcast_event(ReloadEvent, 0);
}

bool log_base::would_log(int level) const {
	/* is any of the child log nodes interested in this level of message? */

	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (!i->second.is_child())
			continue;
		if (((log_node *)i->second.get_node())->will_log(_LOG_INFO, level))
			return true;
	}

	return _force_stderr;
}

log_base &log_base::instance() {
	return g_mrd->g_rlog;
}

bool log_base::change_context(int level) {
	_current = _LOG_INFO;
	_level = level;

	bool b = would_log(level);
	_base.set_decision(b);
	return b;
}

base_stream &log_base::current_context() {
	return _base;
}

void log_base::force_stderr() {
	_force_stderr = true;
}

bool log_base::attach_node(log_node *n) {
	if (!n || !n->check_startup()) {
		delete n;
		return false;
	}

	node *was = get_child(n->name());

	if (was) {
		remove_child(was->name());
	}

	add_child(n);

	return true;
}

void log_base::dettach_node(log_node *n) {
	if (n)
		remove_child(n->name());
}

bool log_base::call_method(int id, base_stream &out,
			   const std::vector<std::string> &args) {
	switch (id) {
	case log_method_attach:
		return attach_node(args);
	}

	return node::call_method(id, out, args);
}

bool log_base::negate_method(int id, base_stream &out,
			     const std::vector<std::string> &args) {
	if (id == log_method_attach) {
		if (args.empty())
			return false;

		log_node *n = (log_node *)get_child(args[0].c_str());

		if (n) {
			remove_child(args[0].c_str());
		}

		return true;
	}

	return node::negate_method(id, out, args);
}

void log_base::flushed(const char *str, bool newline) {
	for (properties::const_iterator i = m_properties.begin();
			i != m_properties.end(); ++i) {
		if (!i->second.is_child())
			continue;

		log_node *n = (log_node *)i->second.get_node();

		if (n->will_log(_current, _level))
			n->log(_current, _level, str, newline);
	}

	if (_force_stderr) {
		fprintf(stderr, "%s%s", str, newline ? "\n" : "");
	}
}

static inline bool _as_int(const char *v, int &value) {
	char *end;
	value = strtol(v, &end, 10);
	if (*end)
		return false;
	return true;
}

bool log_node::parse_infolevel(const char *v, int &value) {
	if (!strcmp(v, "all")) {
		value = EVERYTHING;
	} else if (!strcmp(v, "internal_flow")) {
		value = INTERNAL_FLOW;
	} else if (!strcmp(v, "message_content")) {
		value = MESSAGE_CONTENT;
	} else if (!strcmp(v, "message_sig")) {
		value = MESSAGE_SIG;
	} else if (!strcmp(v, "message_err")) {
		value = MESSAGE_ERR;
	} else if (!strcmp(v, "extradebug")) {
		value = EXTRADEBUG;
	} else if (!strcmp(v, "debug")) {
		value = DEBUG;
	} else if (!strcmp(v, "verbose")) {
		value = VERBOSE;
	} else if (!strcmp(v, "normal")) {
		value = NORMAL;
	} else {
		return _as_int(v, value);
	}

	return true;
}

bool log_base::attach_node(const std::vector<std::string> &args) {
	if (args.empty())
		return false;

	log_node *n = 0;
	int val = 5;

	if (args[0] == "syslog") {
		if (args.size() > 1) {
			if (!log_node::parse_infolevel(args[1].c_str(), val))
				return false;
		}
		n = new syslog_log_node(this, "syslog", val);
	} else if (args[0] == "stderr") {
		if (args.size() > 1) {
			if (!log_node::parse_infolevel(args[1].c_str(), val))
				return false;
		}
		n = new file_log_node(this, "stderr", val, stderr);
	} else if (args.size() > 1) {
		bool flush = true;
		if (args.size() > 2) {
			if (!log_node::parse_infolevel(args[2].c_str(), val))
				return false;
			if (args.size() > 3) {
				if (args[3] == "no-flush")
					flush = true;
				else
					return false;
			}
		}
		n = new file_log_node(this, args[0].c_str(), val,
				      args[1].c_str(), flush);
	}

	if (!n)
		return false;

	attach_node(n);

	return true;
}

const char *stream_type_format_parameter(bool) {
	return "b";
}

const char *stream_type_format_parameter(int) {
	return "i";
}

const char *stream_type_format_parameter(uint32_t) {
	return "u";
}

const char *stream_type_format_parameter(uint64_t) {
	return "llu";
}

const char *stream_type_format_parameter(const char *) {
	return "s";
}

const char *stream_type_format_parameter(const void *) {
	return "p";
}

void stream_push_formated_type(base_stream &os, bool val) {
	os.append_chunk(val ? "true" : "false");
}

void stream_push_formated_type(base_stream &os, int val) {
	os.nprintf(32, "%i", val);
}

void stream_push_formated_type(base_stream &os, uint32_t val) {
	os.nprintf(32, "%u", val);
}

void stream_push_formated_type(base_stream &os, uint64_t val) {
	os.nprintf(64, "%llu", val);
}

void stream_push_formated_type(base_stream &os, const char *val) {
	os.append_chunk(val ? val : "(null)");
}

void stream_push_formated_type(base_stream &os, const void *val) {
	os.nprintf(32, "%p", val);
}

#ifdef __s390__
const char *stream_type_format_parameter(size_t) {
	return "u";
}

void stream_push_formated_type(base_stream &os, size_t val) {
	os.nprintf(32, "%z", val);
}
#endif

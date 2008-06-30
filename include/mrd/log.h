/*
 * Multicast Routing Daemon (MRD)
 *   log.h
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

#ifndef _mrd_log_h_
#define _mrd_log_h_

#include <cstdio>
#include <string>
#include <assert.h>

#include <mrd/node.h>

class base_stream;

class stream_flusher {
public:
	virtual ~stream_flusher();

	virtual void flushed(const char *buffer, bool newline) = 0;
};

const char *stream_type_format_parameter(bool);
const char *stream_type_format_parameter(int);
const char *stream_type_format_parameter(uint32_t);
const char *stream_type_format_parameter(uint64_t);
const char *stream_type_format_parameter(const char *);
const char *stream_type_format_parameter(const void *);
void stream_push_formated_type(base_stream &, bool val);
void stream_push_formated_type(base_stream &, int val);
void stream_push_formated_type(base_stream &, uint32_t val);
void stream_push_formated_type(base_stream &, uint64_t val);
void stream_push_formated_type(base_stream &, const char *val);
void stream_push_formated_type(base_stream &, const void *val);


#ifdef __s390__
const char *stream_type_format_parameter(size_t);
void stream_push_formated_type(base_stream &, size_t val);
#endif

/*!
 * base log stream
 */
class base_stream {
public:
	base_stream();
	base_stream(stream_flusher *);
	~base_stream();

	/*! appends a new string chunk to the stream buffer */
	void append_chunk(const char *);
	void append_chunk(const char *, int);
	/*! requests a buffer part of minimal size n for direct writing.
	 * if there isn't enough space, returns NULL */
	char *req_buffer(int n);
	/*! after directly accessing the buffer, must commit changes
	 * of n characters */
	void commit_change(int n);
	/*! helper method */
	void nprintf(int n, const char *format, ...);
	/*! clears the stream buffer */
	void clear();
	/*! returns a null-terminated string pointer to the stream buffer */
	const char *str() const;

	/*! provides printf-like semantics to base_stream */
	base_stream &printf(const char *, ...);

	base_stream &newl();

	template <typename T>
	base_stream &write(const T &t) {
		stream_push_formated_type(*this, t);
		return *this;
	}

	base_stream &write(const char *val) {
		append_chunk(val);
		return *this;
	}

	template <typename T>
	base_stream &writeline(const T &t) {
		stream_push_formated_type(*this, t);
		return newl();
	}

	base_stream &writeline(const char *val) {
		append_chunk(val);
		return newl();
	}

	/*! simulates POSIX's perror using the internal logging mechanism */
	void perror(const char *);

	void start_formating(const char *);
	base_stream &end_formating();
	void advance_format();
	void check_format_parameter(const char *);

	template <typename T>
	void push_format_argument(const T &t) {
		check_format_parameter(stream_type_format_parameter(t));
		stream_push_formated_type(*this, t);
		advance_format();
	}

	template <typename T1> base_stream &
	xprintf(const char *format, const T1 &t1) {
		start_formating(format);
		push_format_argument(t1);
		return end_formating();
	}

	template <typename T1, typename T2> base_stream &
	xprintf(const char *format, const T1 &t1, const T2 &t2) {
		start_formating(format);
		push_format_argument(t1);
		push_format_argument(t2);
		return end_formating();
	}

	template <typename T1, typename T2, typename T3> base_stream &
	xprintf(const char *format, const T1 &t1, const T2 &t2, const T3 &t3) {
		start_formating(format);
		push_format_argument(t1);
		push_format_argument(t2);
		push_format_argument(t3);
		return end_formating();
	}

	template <typename T1, typename T2, typename T3,
		  typename T4> base_stream &
	xprintf(const char *format, const T1 &t1, const T2 &t2, const T3 &t3,
		const T4 &t4) {
		start_formating(format);
		push_format_argument(t1);
		push_format_argument(t2);
		push_format_argument(t3);
		push_format_argument(t4);
		return end_formating();
	}

	template <typename T1, typename T2, typename T3,
		  typename T4, typename T5> base_stream &
	xprintf(const char *format, const T1 &t1, const T2 &t2, const T3 &t3,
		const T4 &t4, const T5 &t5) {
		start_formating(format);
		push_format_argument(t1);
		push_format_argument(t2);
		push_format_argument(t3);
		push_format_argument(t4);
		push_format_argument(t5);
		return end_formating();
	}

	template <typename T1, typename T2, typename T3,
		  typename T4, typename T5, typename T6> base_stream &
	xprintf(const char *format, const T1 &t1, const T2 &t2, const T3 &t3,
		const T4 &t4, const T5 &t5, const T6 &t6) {
		start_formating(format);
		push_format_argument(t1);
		push_format_argument(t2);
		push_format_argument(t3);
		push_format_argument(t4);
		push_format_argument(t5);
		push_format_argument(t6);
		return end_formating();
	}

	/*! increase indenting level */
	void inc_level();
	/*! decrease indenting level */
	void dec_level();

	/*! produce n spaces of output */
	void spaces(int n);

	/*!
	 * controls whether a stream flush distributes the buffer
	 * for logging or not
	 */
	void set_decision(bool);

	/*!
	 * flushes the stream buffer. if decision=true, all log_nodes
	 * are notified and prompted to log
	 */
	void flush();

protected:
	void ident_start();
	void append_chunk(const char *, int, bool);
	char *req_buffer(int, bool);

	stream_flusher *fl;
	int level;
	bool dec;

	char buffer[256];
	int ptr;

	const char *currfmt;
};

inline void base_stream::start_formating(const char *fmt) {
	assert(currfmt == 0);
	currfmt = fmt;
	advance_format();
}

inline base_stream &base_stream::end_formating() {
	assert(*currfmt == 0);
	currfmt = 0;
	return *this;
}

inline void base_stream::check_format_parameter(const char *param) {
	assert(currfmt != 0);
	assert(strncmp(currfmt + 1, param, strlen(param)) == 0);

	currfmt += 1 + strlen(param);
}

class log_base;

/*!
 * log nodes are notified by log_base whenever there is info to be
 * logged. i.e. after a base_stream::flush
 */
class log_node : public node {
public:
	log_node(log_base *, const char *name, int infolevel);

	bool check_startup();

	void set_level(const char *);
	bool set_property(const char *, const char *);

	static bool parse_infolevel(const char *, int &);

	/*! method called by log_base with logging info */
	virtual void log(int, int, const char *, bool newline) = 0;

protected:
	bool will_log(int, int) const;

	property_def *infolevel;

	friend class log_base;
};

/*! syslog based log_node */
class syslog_log_node : public log_node {
public:
	syslog_log_node(log_base *, const char *, int);
	~syslog_log_node();

	bool check_startup();
	void log(int, int, const char *, bool newline);
};

class tb_log_node : public log_node {
public:
	tb_log_node(log_base *, const char *name, int infolevel);

protected:
	const char *timestamp(char *buffer, size_t length) const;
};

/*! file based log_node (also supports stderr) */
class file_log_node : public tb_log_node {
public:
	file_log_node(log_base *, const char *, int, const char *, bool flush);
	file_log_node(log_base *, const char *, int, FILE *);
	~file_log_node();

	bool check_startup();
	void log(int, int, const char *, bool newline);

	void event(int, void *);

	FILE *_fp;
	std::string _base_filename;
	property_def *_flush;
};

enum {
	FATAL		= 0,
	WARNING		= 1 << 0,
	NORMAL		= 1 << 1,
	VERBOSE		= 1 << 2,
	DEBUG		= 1 << 3,
	EXTRADEBUG	= 1 << 4,
	MESSAGE_ERR	= 1 << 5,
	MESSAGE_SIG	= 1 << 6,
	MESSAGE_CONTENT	= 1 << 7,
	INTERNAL_FLOW	= 1 << 8,
	EVERYTHING	= 0xffffff
};

/*!
 * provides the architecture's logging interface
 */
class log_base : public node, public stream_flusher {
public:
	log_base(node *);
	~log_base();

	const char *description() const;

	bool check_startup();

	static log_base &instance();

	bool change_context(int level);
	base_stream &current_context();

	void force_stderr();

	/*! returns true if would log at the specified level */
	bool would_log(int level) const;

	/*! attaches a new logging node to the architecture */
	bool attach_node(log_node *);
	void dettach_node(log_node *);

	bool call_method(int, base_stream &,
			 const std::vector<std::string> &);
	bool negate_method(int, base_stream &,
			   const std::vector<std::string> &);

	enum {
		ReloadEvent = 'R',
	};

	void reload_logs();

protected:
	void flushed(const char *, bool);

	void remove_child_node(node *);

	bool attach_node(const std::vector<std::string> &);

	int _current, _level;
	bool _force_stderr;

	base_stream _base;
};

#endif


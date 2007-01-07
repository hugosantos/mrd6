/*
 * Multicast Routing Daemon (MRD)
 *   console.h
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

#ifndef _mrd_console_h_
#define _mrd_console_h_

#include <mrd/address.h>
#include <mrd/log.h>
#include <mrd/mrd.h>
#include <mrd/node.h>
#include <mrd/parser.h>
#include <mrd/timers.h>

#include <stack>
#include <string>
#include <set>
#include <deque>
#include <list>
#include <map>
#include <functional>

class mrd;

class console_connection;

class console_module : public mrd_module, public node {
public:
	console_module(mrd *m, void *dlh);
	~console_module();

	const char *description() const;

	bool check_startup();
	void shutdown();

	bool call_method(int id, base_stream &,
			 const std::vector<std::string> &);
	bool negate_method(int id, base_stream &,
			   const std::vector<std::string> &);
	bool output_info(base_stream &ctx, const std::vector<std::string> &) const;

#ifndef CONSOLE_NO_TELNET
	void new_client(uint32_t);
#endif
	void new_unix_client(uint32_t);

	void release_connection(console_connection *);

	bool password_for(const inet6_addr &, const char *, std::string &) const;

#ifndef CONSOLE_NO_TELNET
	socket0<console_module> srvsock;
#endif
	socket0<console_module> unix_srvsock;

	std::list<console_connection *> connections;

	struct auth_desc {
		std::string username;
		std::string password;
	};

	typedef std::map<inet6_addr,
			 std::list<auth_desc>,
			 std::greater<inet6_addr> > allow_local_def;

	allow_local_def acl;

	bool allow_addr(const std::vector<std::string> &);
	bool deny_addr(const std::vector<std::string> &);
	bool allow_local(const std::vector<std::string> &);
	bool attach_log(base_stream &, const std::vector<std::string> &);

	bool show_history(base_stream &);

	console_connection *calling_connection(base_stream &) const;
};

extern console_module *console;

class console_log_node : public tb_log_node {
public:
	console_log_node(console_connection *);

	void rename(const char *);

	void log(int, int, const char *, bool newline);

	console_connection *_conn;
	std::string _buf;
};

class console_connection : public stream_flusher {
public:
	console_connection(mrd *core, int);
	virtual ~console_connection() {}

	virtual bool check_startup();
	void shutdown();
	void doom();

	virtual void release();

	void data_available(uint32_t);
	virtual void process_input(int) = 0;

	virtual bool process_line(const char *);

	void process_deep_line(parser_context *);

	enum {
		CONSISTENCY_ERROR = -3,
		INPUT_ERROR = -2,
		END_LINE = -1,
		OK = 0
	};

	int transform(parser_context *, node *, node::content_type,
		      node * &) const;
	int transform(parser_context *, node *, node::content_type,
		      node * &, std::string &) const;

	void writeclient(const char *);

	virtual void flushed(const char *, bool) = 0;

	virtual void dump_history(base_stream &) const;

	virtual void log(bool end);

	mrd *m_mrd;

	bool is_doomed;

	socket0<console_connection> sock;

	mutable base_stream _output;

	unsigned char buffer[1024];

	std::string bufbuffer;

	int advance_one(parser_context *, node *);
	int check_termination(parser_context *, node *);
	void dump_partial(const char *);
	void dump_partial(node *, parser_context *, bool);

	bool autoclose;
	console_log_node *clog;
};

class telnet_console_connection : public console_connection {
public:
	telnet_console_connection(mrd *core, int, const inet6_addr &, uint32_t);
	~telnet_console_connection();

	bool check_startup();
	void release();

	const inet6_addr &peeraddr() const { return c_peeraddr; }

	bool authenticate(const char *);

	void process_input(int);

	void flushed(const char *, bool);

	bool process_line(const char *);

	void dump_history(base_stream &) const;
	void log(bool end);
private:
	enum {
		NoState,
		WaitingPassword,
		GotAllData,
	};

	bool process_cmd();

	bool tabcomplete();

	void show_prompt();
	void set_prompt(const char *);

	void clearline();
	void redisplay_input();

	void cmd(char c, char opt);

	void release_connection();

	void history_up();
	void history_down();

	timer<telnet_console_connection> conn_timer;

	std::deque<unsigned char> ctlbuf;

	int pmode;

	bool will_echo;
	bool should_echo;
	bool input_is_updated;

	std::string inputbuf;
	std::string tmp_inputbuf;

	std::vector<std::string> history;
	int history_pos;

	int authenticate_state;
	std::string username;

	std::string prompt;

	inet6_addr c_peeraddr;
};

class unix_console_connection : public console_connection {
public:
	unix_console_connection(mrd *core, int);

	void process_input(int);

	void release();

	void flushed(const char *, bool);
};

#endif


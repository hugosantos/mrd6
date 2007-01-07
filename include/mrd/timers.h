/*
 * Multicast Routing Daemon (MRD)
 *   timers.h
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

#ifndef _mrd_timers_h_
#define _mrd_timers_h_

#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <stdint.h>

#include <list>
#include <string>
#include <functional>

class base_stream;

struct time_duration {
	time_duration(int);
	int32_t value;
};

inline time_duration::time_duration(int val)
	: value(val) {}

class tval {
private:
	timeval v;
public:
	tval() { v.tv_sec = 0; v.tv_usec = 0; }
	tval(time_t secs) { v.tv_sec = secs; v.tv_usec = 0; }
	tval(time_t secs, suseconds_t usecs) { v.tv_sec = secs; v.tv_usec = usecs; }

	tval operator + (const tval &) const;
	int32_t operator - (const tval &) const; // milisecs

	tval &operator += (const tval &tv) {
		v.tv_usec += tv.v.tv_usec;
		if (v.tv_usec > 1000000) {
			v.tv_sec ++;
			v.tv_usec -= 1000000;
		}
		v.tv_sec += tv.v.tv_sec;
		return *this;
	}

	tval &operator += (uint32_t diff) {
		v.tv_usec += (diff % 1000) * 1000;
		v.tv_sec += diff / 1000;
		if (v.tv_usec > 1000000) {
			v.tv_usec -= 1000000;
			v.tv_sec ++;
		}

		return *this;
	}

	tval &operator = (const tval &tv) {
		v = tv.v;
		return *this;
	}

	bool operator < (const tval &tv) const {
		return v.tv_sec < tv.v.tv_sec || (v.tv_sec == tv.v.tv_sec && v.tv_usec < tv.v.tv_usec);
	}

	bool operator == (const tval &tv) const {
		return v.tv_sec == tv.v.tv_sec && v.tv_usec == tv.v.tv_usec;
	}

	bool operator <= (const tval &tv) const {
		return v.tv_sec < tv.v.tv_sec || (v.tv_sec == tv.v.tv_sec && v.tv_usec <= tv.v.tv_usec);
	}

	tval diff(const tval &) const;

	uint32_t round_milisecs() const {
		return v.tv_sec * 1000 + v.tv_usec / 1000;
	}

	uint32_t round_secs() const {
		return v.tv_sec + (v.tv_usec >= 5000000 ? 1 : 0);
	}

	void update_to_now() {
		gettimeofday(&v, 0);
	}

	static tval now() {
		tval tv;
		tv.update_to_now();
		return tv;
	}

	const timeval &as_timeval() const { return v; }

	time_t secs() const { return v.tv_sec; }
	suseconds_t usecs() const { return v.tv_usec; }

	base_stream &print_to(base_stream &) const;
};

class timer_base {
public:
	timer_base(const std::string &);
	timer_base(const std::string &, uint32_t interval, bool repeat,
		   uint32_t perturb = 0);
	timer_base(const timer_base &);
	virtual ~timer_base();

	std::string name;

	/*! returns true if the timer is running */
	bool is_running() const;
	/*! returns the time left in miliseconds */
	uint32_t time_left() const;
	uint32_t get_interval() const;

	time_duration time_left_d() const;

	bool start(bool immediatly = false);
	bool start(uint32_t interval, bool repeat, bool immediatly = false,
		   uint32_t perturb = 0);
	bool stop();

	bool restart(bool immediatly = false);

	void update(uint32_t interval, bool repeat, uint32_t perturb = 0);

	bool start_or_update(uint32_t interval, bool repeat,
			     bool immediatly = false, uint32_t perturb = 0);

	virtual void callback() = 0;

	base_stream &print_to(base_stream &) const;

protected:
	bool _running, _repeat;
	uint32_t _interval, _perturb;

	uint32_t _target, _extra;

	friend class timermgr;
};

inline timer_base::timer_base(const std::string &n)
	: name(n), _running(false), _repeat(false), _interval(0), _perturb(0),
	  _target(0), _extra(0) {}

inline timer_base::timer_base(const std::string &n, uint32_t interval, bool repeat,
		              uint32_t perturb)
	: name(n), _running(false), _repeat(repeat), _interval(interval),
	  _perturb(perturb), _target(0), _extra(0) {}

inline bool timer_base::is_running() const {
	return _running;
}

inline uint32_t timer_base::get_interval() const {
	return _interval;
}

inline time_duration timer_base::time_left_d() const {
	return time_duration(time_left());
}

inline bool timer_base::restart(bool immediatly) {
	return start_or_update(_interval, _repeat, immediatly);
}

inline bool timer_base::start_or_update(uint32_t interval, bool repeat,
					bool immediatly, uint32_t perturb) {
	if (_running) {
		update(interval, repeat, perturb);
		return true;
	} else {
		return start(interval, repeat, immediatly, perturb);
	}
}

template<typename Holder>
class timer : public timer_base {
public:
	typedef std::mem_fun_t<void, Holder> callback_def;

	timer(const std::string &, Holder *h, callback_def c);
	timer(const std::string &, Holder *h, callback_def c,
			uint32_t interval, bool repeat);
	timer(const timer<Holder> &);

	void callback();

protected:
	Holder *_h;
	callback_def _cb;
};

template<typename H> inline timer<H>::timer(const std::string &name, H *h,
						timer<H>::callback_def c)
	: timer_base(name), _h(h), _cb(c) {}

template<typename H> inline timer<H>::timer(const std::string &name, H *h,
					timer<H>::callback_def c,
					uint32_t interval, bool repeat)
	: timer_base(name, interval, repeat), _h(h), _cb(c) {}

template<typename H> inline timer<H>::timer(const timer<H> &original)
	: timer_base(original), _h(original._h), _cb(original._cb) {}

template<typename H> inline void timer<H>::callback() {
	_cb(_h);
}

template<typename Holder, typename Arg>
class timer1 : public timer_base {
public:
	typedef std::mem_fun1_t<void, Holder, Arg &> callback_def;

	timer1(const std::string &, Holder *h, callback_def c, const Arg &a);
	timer1(const std::string &, Holder *h, callback_def c, const Arg &a,
					uint32_t interval, bool repeat);
	timer1(const timer1<Holder, Arg> &);

	void callback();

	const Arg &argument() const { return _arg; }

protected:
	Holder *_h;
	callback_def _cb;
	Arg _arg;
};

template<typename H, typename A> inline timer1<H, A>::timer1(const std::string &name, H *h,
						timer1<H, A>::callback_def c, const A &a)
	: timer_base(name), _h(h), _cb(c), _arg(a) {}

template<typename H, typename A> inline timer1<H, A>::timer1(const std::string &name, H *h,
					timer1<H, A>::callback_def c, const A &a,
					uint32_t interval, bool repeat)
	: timer_base(name, interval, repeat), _h(h), _cb(c), _arg(a) {}

template<typename H, typename A> inline timer1<H, A>::timer1(const timer1<H, A> &original)
	: timer_base(original), _h(original._h), _cb(original._cb), _arg(original._arg) {}

template<typename H, typename A> inline void timer1<H, A>::callback() {
	_cb(_h, _arg);
}

/*!
 * \class timermgr mrd/timers.h
 * \brief Timer manager class.
 */
class timermgr {
public:
	timermgr();
	virtual ~timermgr();

	bool check_startup();
	void shutdown();

	bool time_left(timeval &);

	bool output_info(base_stream &, bool) const;

	void start_timer(timer_base *);
	void stop_timer(timer_base *);
	void update_timer(timer_base *, uint32_t, bool, uint32_t);

	bool handle_event();
	void timed_out_event();

	void start_timer(timer_base *, uint32_t, uint32_t);
	void clone_position(const timer_base *, timer_base *);

	uint32_t time_left(const timer_base *) const;

private:
	void handle_timer_event();
	void update_taccum();

	typedef std::list<timer_base *> tq_def;
	tq_def tq;

	uint32_t clk_tck;
	clock_t lastclk;
	uint32_t taccum;
};

static inline const char *stream_type_format_parameter(const time_duration &) {
	return "{duration}";
}

void stream_push_formated_type(base_stream &os, const time_duration &);

#endif


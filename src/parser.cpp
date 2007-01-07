/*
 * Multicast Routing Daemon (MRD)
 *   parser.cpp
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

#include <mrd/parser.h>

#include <stdarg.h>
#include <ctype.h>

enum {
	_INVALID,
	_LCURLY, _RCURLY,
	_LPARENT, _RPARENT,
	_TERM,
	_EQUAL,
	_PLUSEQUAL,
	_DOT, _COMMA,
	_TOKEN,
	_PARTIAL_TOKEN,
	_STRING,

	_NEWLINE,
	_OCOMMENT,
	_CCOMMENT,
	_LCOMMENT,
};

static const char *_token_names[] = {
	"end of input",
	"open-braces", "close-braces",
	"left-parenthesis", "right-parenthesis",
	"colon",
	"equal",
	"plus-equal",
	"dot", "comma",
	"token",
	"partial token",
	"quoted string"
};

const char *parser_context::token_name(token_type tok) {
	return _token_names[tok];
}

parser_context::parser_context()
	: m_current_line(1), m_input(0), m_input_pointer(0),
		m_input_line_start(0), m_partial(false) {
}

parser_context::parser_context(const char *input, bool partial)
	: m_current_line(1), m_input(input), m_input_pointer(input),
		m_input_line_start(input), m_partial(partial) {
}

parser_context::parser_context(const parser_context &ctx)
	: m_current(ctx.m_current), m_current_line(ctx.m_current_line),
		m_input(ctx.m_input), m_input_pointer(ctx.m_input_pointer),
		m_input_line_start(ctx.m_input_line_start),
		m_partial(ctx.m_partial) {
}

parser_context &parser_context::operator = (const parser_context &ctx) {
	m_current = ctx.m_current;
	m_current_line = ctx.m_current_line;
	m_input = ctx.m_input;
	m_input_pointer = ctx.m_input_pointer;
	m_input_line_start = ctx.m_input_line_start;
	m_partial = ctx.m_partial;

	return *this;
}

parser_context::symbol::symbol()
	: line(0), sym(NONE) {}

parser_context::symbol::symbol(int l, token_type tok, const std::string &text)
	: line(l), sym(tok), value(text) {}

parser_context::symbol::symbol(const symbol &sym)
	: line(sym.line), sym(sym.sym), value(sym.value) {}

std::string parser_context::current_line() const {
	const char *ptr = m_input_line_start;

	while (*ptr && *ptr != '\n')
		ptr++;

	if (*ptr == '\n')
		ptr--;

	return std::string(m_input_line_start, ptr);
}

int parser_context::read() {
	if (m_symq.empty()) {
		int res, sym;
		const char *symstart = m_input_pointer;

		if ((res = read_token(false, &sym, &symstart)) < 1)
			return res;

		const char *symend = m_input_pointer;

		if (sym == _STRING) {
			symstart++;
			symend--;
		}

		m_current = symbol(m_current_line, (token_type)sym,
				   std::string(symstart, symend));

		m_symq.push_back(m_current);
	} else {
		m_current = m_symq.front();
	}

	return 1;
}

int parser_context::eat() {
	int res;

	if ((res = read()) < 1)
		return res;

	m_symq.pop_front();

	return 1;
}

int parser_context::eat(token_type tok) {
	return eat(1, tok);
}

int parser_context::eat(int count, ...) {
	int res = eat();
	if (res < 1)
		return res;
	va_list vl;
	va_start(vl, count);
	for (int i = 0; i < count; i++) {
		if (va_arg(vl, int) == m_current.sym) {
			va_end(vl);
			return 1;
		}
	}
	va_end(vl);
	return -1;
}

int parser_context::read_token(bool strict, int *sym, const char **symstart,
			       bool eat) {
	int res, readnum;
	int pointer = 0, prevpointer = 0;
	int linenumber = m_current_line;
	int state = 0;
	const char *currline = m_input_line_start;
	int commentlevel = 0;

	while (1) {
		if ((res = parse_one(m_input_pointer + pointer, state, sym,
				     &readnum)) < 1) {
			return res;
		}

		if (strict) {
			break;
		}

		if (*sym == _OCOMMENT) {
			int commentlen = readnum;

			pointer += readnum;
			commentlevel++;

			state = 1;

			while (commentlevel > 0) {
				if ((res = parse_one(m_input_pointer + pointer,
						     state, sym, &readnum)) < 1)
					return res;
				if (*sym == _NEWLINE) {
					linenumber++;
					currline = m_input_pointer
						    + pointer
						    + readnum;
				} else if (*sym == _OCOMMENT) {
					commentlevel++;
				} else if (*sym == _CCOMMENT) {
					commentlevel--;
				}
				pointer += readnum;
			}

			pointer -= commentlen;

			state = 0;
		} else if (*sym == _LCOMMENT) {
			while (1) {
				if ((res = parse_one(m_input_pointer + pointer,
						     1, sym, &readnum)) < 1)
					return res;
				if (*sym == _NEWLINE) {
					linenumber++;
					currline = m_input_pointer
						    + pointer
						    + readnum;
					break;
				}
				pointer += readnum;
			}
		} else if (*sym == _NEWLINE) {
			linenumber++;
			currline = m_input_pointer + pointer + readnum;
		} else if (*sym != -1) {
			break;
		}

		prevpointer = pointer;
		pointer += readnum;
	}

	if (symstart)
		*symstart = m_input_pointer + pointer;

	if (eat) {
		m_current_line = linenumber;

		m_input_pointer += pointer + readnum;
		m_input_line_start = currline;
	}

	return 1;
}

static inline bool is_token_char(char c) {
	return isalnum(c) || c == ':' || c == '/' || c == '-' || c == '_' || c == '.';
}

int parser_context::parse_one(const char *input, int state, int *sym, int *readnum) const {
	if (!input || !*input)
		return 0;

	/* comment state */
	if (state == 1) {
		if (input[0] == '\n') {
			*sym = _NEWLINE;
			*readnum = 1;
		} else if (input[0] == '/' && input[1] == '*') {
			*sym = _OCOMMENT;
			*readnum = 2;
		} else if (input[0] == '*' && input[1] == '/') {
			*sym = _CCOMMENT;
			*readnum = 2;
		} else {
			*sym = -1;
			int i = 0;

			while (input[i]) {
				if (input[i] == '\n') {
					break;
				} else if (input[i] == '/' && input[i+1] == '*') {
					break;
				} else if (input[i] == '*'  &&input[i+1] == '/') {
					break;
				}
				i++;
			}

			*readnum = i;
		}
	} else {
		int c = -1, s = -1;

		if (input[0] == '\n') {
			c = 1;
			s = _NEWLINE;
		} else if (isspace(input[0])) {
			c = 1;
			for (; isspace(input[c]); c++);
		} else if (input[0] == '/' && input[1] == '*') {
			c = 2;
			s = _OCOMMENT;
		} else if (input[0] == '/' && input[1] == '/') {
			c = 2;
			s = _LCOMMENT;
		} else if (input[0] == '*' && input[1] == '/') {
			c = 2;
			s = _CCOMMENT;
		} else if (input[0] == '{') {
			c = 1;
			s = _LCURLY;
		} else if (input[0] == '}') {
			c = 1;
			s = _RCURLY;
		} else if (input[0] == '(') {
			c = 1;
			s = _LPARENT;
		} else if (input[0] == ')') {
			c = 1;
			s = _RPARENT;
		} else if (input[0] == ';') {
			c = 1;
			s = _TERM;
		} else if (input[0] == '=') {
			c = 1;
			s = _EQUAL;
		} else if (input[0] == '+' && input[1] == '=') {
			c = 2;
			s = _PLUSEQUAL;
		} else if (input[0] == '.') {
			c = 1;
			s = _DOT;
		} else if (input[0] == ',') {
			c = 1;
			s = _COMMA;
		} else if (is_token_char(input[0])) {
			c = 1;
			for (; is_token_char(input[c]); c++);

			if (input[c] == '?') {
				c++;
				s = _PARTIAL_TOKEN;
			} else {
				s = _TOKEN;
			}
		} else if (input[0] == '?') {
			c = 1;
			s = _PARTIAL_TOKEN;
		} else if (input[0] == '*') {
			c = 1;
			s = _TOKEN;
		} else if (input[0] == '\"') {
			c = 1;
			for (; input[c] && input[c] != '\"'; c++);
			if (input[c] == '\"') {
				c++;
				s = _STRING;
			} else {
				c = -1;
			}
		}

		*readnum = c;
		*sym = s;

		if (*readnum == -1)
			return -1;
	}

	return 1;
}


/*
 * Multicast Routing Daemon (MRD)
 *   parser.h
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

#ifndef _mrd_parser_h_
#define _mrd_parser_h_

#include <sys/types.h>

#include <map>
#include <vector>
#include <list>
#include <string>

class parser_context {
public:
	parser_context();
	parser_context(const char *input, bool partial = false);
	parser_context(const parser_context &);

	parser_context &operator = (const parser_context &);

	enum token_type {
		NONE,
		LCURLY, RCURLY,
		LPARENT, RPARENT,
		TERM,
		EQUAL,
		PLUSEQUAL,
		DOT, COMMA,

		/* identifier, integer, address, etc. */
		TOKEN,
		/* TOKEN directly followed by a '?' */
		PARTIAL_TOKEN,
		/* quoted string */
		STRING,
	};

	static const char *token_name(token_type);

	struct symbol {
		symbol();
		symbol(int, token_type, const std::string &);
		symbol(const symbol &);

		int line;
		token_type sym;
		std::string value;
	};

	int current_line_number() const { return m_current_line; }
	std::string current_line() const;
	const char *current_input() const { return m_input_pointer; }
	int current_column() const { return m_input_pointer - m_input_line_start; }

	// -1 parsing error
	//  0 no more symbols
	//  1 parsed with success
	int read();
	int eat();
	int eat(token_type);
	int eat(int, ...);

	const symbol &head() const { return m_current; }

private:
	int read_token(bool, int *, const char ** = 0, bool = true);

	int parse_one(const char *input, int state, int *sym, int *readnum) const;

	symbol m_current;
	int m_current_line;

	std::list<symbol> m_symq;

	const char *m_input;
	const char *m_input_pointer;
	const char *m_input_line_start;

	bool m_partial;
};

#endif


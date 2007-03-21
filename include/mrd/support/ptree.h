/*
 * Multicast Routing Daemon (MRD)
 *   ptree.h
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

/*
 * Patricia tree implementation, compressed binary trie
 *
 *   based on
 *
 * PATRICIA - Pratical Algorithm to Retrieve Information Coded
 *            in Alphanumeric - Donald R. Morrison 1968
 *
 */

#ifndef _Ptree_h_
#define _Ptree_h_

#include <stdint.h>
#include <algorithm>
#include <mrd/log.h>

/* Patricia nodes MUST derive from ptree_node */
struct ptree_node {
	ptree_node *_t_parent, *_t_left, *_t_right;

	/* Black nodes are data-nodes supplied by the user,
	 * while white nodes work as glue/decision nodes */
	enum {
		WHITE = 0,
		BLACK = 1
	};

	uint32_t _t_color : 1, _t_bit : 31;
};

/* Simple new/delete based allocator */
template<typename blocktype>
struct _simple_allocator {
	blocktype *request_obj() {
		return new blocktype;
	}
	void return_obj(blocktype *b) {
		delete b;
	}
};

typedef _simple_allocator<ptree_node> ptree_node_allocator;

class base_ptree {
public:
	base_ptree();
	virtual ~base_ptree();

	bool empty() const;
	uint32_t size() const;

	bool remove(ptree_node *node);
	void clear();

	void dump_internal_tree(base_stream &os) const;
	void dump_internal_tree_graphviz(base_stream &os) const;

protected:
	ptree_node *get_parent_node(const ptree_node *n) const;
	ptree_node *_get_first_black() const;
	ptree_node *_a_child_black_node(ptree_node *node) const;
	void _fix_parent(ptree_node *newnode, ptree_node *oldnode);

	void dump_internal_tree(base_stream &os, const ptree_node *node,
				const char *desc) const;
	void dump_internal_tree_graphviz(base_stream &os, const ptree_node *node,
					 const char *color) const;
	virtual void write_prefix(base_stream &, const ptree_node *) const = 0;

	ptree_node *_alloc_white(int bit);
	void _return_white(ptree_node *n);

	struct iterator {
		iterator();
		iterator(ptree_node *);
		iterator(const iterator &);

		ptree_node *increment();

		ptree_node *curr, *prev;
	};

	ptree_node_allocator whites;
	ptree_node *head;
	uint32_t count;
};

/* Patricia implementation */
template <typename key_type, typename node_type>
class ptree : public base_ptree {
public:
	node_type *search(const key_type &key) const {
		if (!head)
			return 0;

		ptree_node *node = head;

		uint32_t bitlen = pnode_prefix_length(key);

		/* descend the binary trie */
		while (node->_t_bit < bitlen) {
			node = pnode_symbol_at(key, node->_t_bit) ?
				node->_t_right : node->_t_left;
			if (!node)
				return 0;
		}

		if (node->_t_bit == bitlen && node->_t_color == node_type::BLACK) {
			if (((node_type *)node)->prefix == key)
				return (node_type *)node;
		}

		return 0;
	}

	node_type *longest_match(const key_type &key) const {
		if (!head)
			return 0;

		ptree_node *node = head, *best = 0;

		uint32_t prevbit = 0, difbit, bitlen = pnode_prefix_length(key);

		/* descend the binary trie */
		while (node && node->_t_bit <= bitlen) {
			if (node->_t_color == ptree_node::BLACK) {
				difbit = _first_dif_bit(((node_type *)node)->prefix,
							key, prevbit, node->_t_bit);

				if (difbit < node->_t_bit)
					break;
				best = node;
			}

			prevbit = node->_t_bit;

			if (pnode_symbol_at(key, node->_t_bit))
				node = node->_t_right;
			else
				node = node->_t_left;
		}

		return (node_type *)best;
	}

	node_type *insert(node_type *newnode) {
		/* prepare node for insertion */
		newnode->_t_parent = 0;
		newnode->_t_left = 0;
		newnode->_t_right = 0;
		newnode->_t_color = ptree_node::BLACK;
		newnode->_t_bit = pnode_prefix_length(newnode->prefix);

		if (!head) {
			/* no head? the new node will be our head */
			head = newnode;
		} else {
			ptree_node *next, *node = head;

			/* descend the binary trie */
			while (node->_t_color == ptree_node::WHITE
				|| node->_t_bit < newnode->_t_bit) {
				if (pnode_symbol_at(newnode->prefix, node->_t_bit))
					next = node->_t_right;
				else
					next = node->_t_left;
				if (!next)
					break;
				node = next;
			}

			/* check the first different bit between the
			 * current node's key and the one being added */
			uint32_t difbit = _first_dif_bit(((node_type *)node)->prefix,
						    newnode->prefix, 0,
						    std::min(node->_t_bit, newnode->_t_bit));

			/* if the difference is handled by one of the
			 * node's parent, go up and aggregate */
			ptree_node *parent = node->_t_parent;
			while (parent && parent->_t_bit >= difbit) {
				node = parent;
				parent = node->_t_parent;
			}

			/* the node's key being added matches exactly with
			 * another one already present in the binary trie */
			if (difbit == newnode->_t_bit && node->_t_bit == newnode->_t_bit) {
				if (node->_t_color == ptree_node::WHITE) {
					/* if the node was white, replace it with
					 * the new black one */
					_fix_parent(newnode, node);
					_return_white(node);
				} else {
					/* else it's a duplicate */
					return 0;
				}

				return newnode;
			}

			/* assert(node->_t_color == ptree_node::BLACK); */

			if (node->_t_bit == difbit) {
				/* the new node will be a leaf */
				newnode->_t_parent = node;
				_pick_set_side(newnode, node);
			} else if (newnode->_t_bit == difbit) {
				/* we'll stick the new node in the middle,
				 * between parent and node */

				ptree_node *black = _a_child_black_node(node);

				/* assert(black); */

				if (pnode_symbol_at(((node_type *)black)->prefix, difbit))
					newnode->_t_right = node;
				else
					newnode->_t_left = node;

				_fix_parent(newnode, node);
			} else {
				/* aggregate, we need a new white node */
				ptree_node *white = _alloc_white(difbit);
				if (!white)
					return 0;

				if (pnode_symbol_at(newnode->prefix, difbit)) {
					white->_t_right = newnode;
					white->_t_left = node;
				} else {
					white->_t_left = newnode;
					white->_t_right = node;
				}

				_fix_parent(white, node);
				newnode->_t_parent = white;
			}
		}

		count ++;

		return newnode;
	}

	node_type *get_parent_node(const node_type *n) const {
		return (node_type *)base_ptree::get_parent_node(n);
	}

	template<typename itertype>
	struct base_iterator : private base_ptree::iterator {
		typedef std::forward_iterator_tag iterator_category;
		typedef itertype value_type;
		typedef ptrdiff_t difference_type;
		typedef itertype *pointer;
		typedef itertype &reference;

		typedef base_iterator<itertype> this_type;

		base_iterator() {}
		base_iterator(itertype *current)
			: base_ptree::iterator((ptree_node *)current) {}
		base_iterator(const this_type &i)
			: base_ptree::iterator(i) {}

		this_type &operator ++() {
			increment();
			return *this;
		}

		this_type operator++(int) {
			return ++this_type(*this);
		}

		pointer operator ->() const {
			return (itertype *)curr;
		}

		reference operator *() const {
			return *(itertype *)curr;
		}

		friend bool operator == (const this_type &i1,
					 const this_type &i2) {
			return i1.curr == i2.curr;
		}

		friend bool operator != (const this_type &i1,
					 const this_type &i2) {
			return !(i1 == i2);
		}
	};

	typedef base_iterator<node_type> iterator;
	typedef base_iterator<const node_type> const_iterator;

	iterator begin() {
		return iterator((node_type *)_get_first_black());
	}

	const_iterator begin() const {
		return const_iterator((const node_type *)_get_first_black());
	}

	iterator end() {
		return iterator(NULL);
	}

	const_iterator end() const {
		return const_iterator(NULL);
	}

private:
	void _pick_set_side(ptree_node *node, ptree_node *parent) {
		/* assert(node->_t_color == ptree_node::BLACK); */

		if (pnode_symbol_at(((node_type *)node)->prefix, parent->_t_bit))
			parent->_t_right = node;
		else
			parent->_t_left = node;
	}

	int _first_dif_bit(const key_type &p1, const key_type &p2, int st,
			   int end) const {
		while (st < end && pnode_symbol_at(p1, st) == pnode_symbol_at(p2, st))
			st++;
		return st;
	}

	void write_prefix(base_stream &os, const ptree_node *n) const {
		os.write(((const node_type *)n)->prefix);
	}
};

#endif


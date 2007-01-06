/*
 * Patricia tree implementation, compressed binary trie
 *
 *   based on
 *
 * PATRICIA - Pratical Algorithm to Retrieve Information Coded
 *            in Alphanumeric - Donald R. Morrison 1968
 *
 * Copyright (C) 2004, 2005, 2006
 *   Universidade de Aveiro, Instituto de Telecomunicacoes - Polo Aveiro
 *
 * Author: Hugo Santos <hsantos@av.it.pt>
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

/* Patricia implementation */
template <typename key_type, typename node_type,
	  typename allocator = _simple_allocator<ptree_node> >
class ptree {
public:
	ptree()
		: head(0), count(0) {
	}

	ptree(const allocator &alloc)
		: head(0), count(0), whites(alloc) {
	}

	~ptree() {
		clear();
	}

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
		while (node && node->_t_bit < bitlen) {
			if (node->_t_color == ptree_node::BLACK) {
				difbit = _first_dif_bit(((node_type *)node)->prefix,
						    key, 0, node->_t_bit);

				if (difbit < prevbit || difbit < node->_t_bit)
					break;
				best = node;
			}

			prevbit = node->_t_bit;

			node = pnode_symbol_at(key, node->_t_bit) ?
				node->_t_right : node->_t_left;
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

	bool remove(node_type *node) {
		if (!head || !node || node->_t_color != node_type::BLACK)
			return false;

		ptree_node *parent = node->_t_parent;

		if (node->_t_left && node->_t_right) {
			/* we are a backbone node, need a replacing white node */
			ptree_node *white = _alloc_white(node->_t_bit);
			if (!white)
				return false;
			if (node->_t_left)
				node->_t_left->_t_parent = white;
			white->_t_left = node->_t_left;
			if (node->_t_right)
				node->_t_right->_t_parent = white;
			white->_t_right = node->_t_right;

			_fix_parent(white, node);
		} else if (node->_t_left) {
			_fix_parent(node->_t_left, node);
		} else if (node->_t_right) {
			_fix_parent(node->_t_right, node);
		} else {
			_fix_parent(0, node);
		}

		/* remove redundant white nodes */
		ptree_node *curr = parent;
		while (curr && curr->_t_color == ptree_node::WHITE) {
			parent = curr->_t_parent;
			if (curr->_t_left && curr->_t_right)
				break;
			else if (curr->_t_left)
				_fix_parent(curr->_t_left, curr);
			else if (curr->_t_right)
				_fix_parent(curr->_t_right, curr);
			else
				_fix_parent(0, curr);
			_return_white(curr);
			curr = parent;
		}

		count --;

		return true;
	}

	void clear() {
		node_type *node = 0;

		/* By removing every black node we also trigger
		 * the removal of all white nodes */
		while ((node = _get_first_black())) {
			remove(node);
		}
	}

	node_type *get_parent_node(const node_type *n) const {
		if (!n)
			return 0;

		ptree_node *nn = (node_type *)n;

		do {
			nn = nn->_t_parent;
		} while (nn && nn->_t_color == ptree_node::WHITE);

		return (node_type *)nn;
	}

	template<typename itertype>
	struct base_iterator {
		typedef std::forward_iterator_tag iterator_category;
		typedef itertype value_type;
		typedef ptrdiff_t difference_type;
		typedef itertype *pointer;
		typedef itertype &reference;

		typedef base_iterator<itertype> this_type;

		base_iterator()
			: _tree(0), _current(0), _prev(0) {}

		base_iterator(const ptree<key_type, node_type, allocator> *tree,
			      itertype *current)
			: _tree(tree), _current(current), _prev(0) {
		}
		base_iterator(const this_type &i)
			: _tree(i._tree), _current(i._current), _prev(i._prev) {
		}

		this_type &operator ++() {
			_tree->_increment(_current, _prev);
			return *this;
		}

		this_type operator++(int) {
			this_type i(*this);
			++(*this);
			return i;
		}

		pointer operator ->() const {
			return _current;
		}

		reference operator *() const {
			return *_current;
		}

		friend bool operator == (const this_type &i1,
					 const this_type &i2) {
			return i1._current == i2._current;
		}

		friend bool operator != (const this_type &i1,
					 const this_type &i2) {
			return i1._current != i2._current;
		}

		const ptree<key_type, node_type, allocator> *_tree;
		itertype *_current, *_prev;
	};

	typedef base_iterator<node_type> iterator;
	typedef base_iterator<const node_type> const_iterator;

	iterator begin() {
		return iterator(this, _get_first_black());
	}

	const_iterator begin() const {
		return const_iterator(this, _get_first_black());
	}

	iterator end() {
		return iterator(this, 0);
	}

	const_iterator end() const {
		return const_iterator(this, 0);
	}

	bool empty() const {
		return head == 0;
	}

	uint32_t size() const {
		return count;
	}

	template<typename itertype>
	void _increment(itertype * &_current, itertype * &prev) const {
		if (!_current)
			return;

		const ptree_node *current = _current;

		do {
			const ptree_node *_prev = prev;
			prev = (itertype *)current;

			if (_prev && _prev == current->_t_left) {
				/* coming from left, go right, or up */
				if (current->_t_right)
					current = current->_t_right;
				else
					current = current->_t_parent;
			} else if (_prev && _prev == current->_t_right) {
				/* coming from right, go up */
				current = current->_t_parent;
			} else if (current->_t_left) {
				current = current->_t_left;
			} else if (current->_t_right) {
				current = current->_t_right;
			} else {
				current = current->_t_parent;
			}
		} while (current && (prev->_t_parent == current
				|| current->_t_color == ptree_node::WHITE));

		_current = (itertype *)current;
	}

	void dump_internal_tree(base_stream &os) const {
		dump_internal_tree(os, head, "root");
	}

	void dump_internal_tree_graphviz(base_stream &os) const {
		os.writeline("graph ptree {");
		os.inc_level();
		dump_internal_tree_graphviz(os, head, "black");
		dump_internal_tree_graphviz(os, head, 0);
		os.dec_level();
		os.writeline("}");
	}

private:
	void dump_internal_tree(base_stream &os, const ptree_node *node, const char *desc) const {
		if (!node)
			return;
		os.xprintf("%s ", desc);
		if (node->_t_color == ptree_node::BLACK)
			os.write(((const node_type *)node)->prefix);
		else
			os.xprintf("white %i", (int)node->_t_bit);
		os.newl();

		os.inc_level();

		dump_internal_tree(os, node->_t_left, "left");
		dump_internal_tree(os, node->_t_right, "right");

		os.dec_level();
	}

	void dump_internal_tree_graphviz(base_stream &os, const ptree_node *node, const char *color) const {
		if (!node)
			return;
		os.xprintf("\"%p\" ", (const void *)node);

		if (color) {
			os.write("[label=\"");
			if (node->_t_color == ptree_node::BLACK)
				os.write(((const node_type *)node)->prefix);
			else
				os.xprintf("white %i", (int)node->_t_bit);
			os.xprintf("\",color=%s];\n", color);

			dump_internal_tree_graphviz(os, node->_t_left, "red");
			dump_internal_tree_graphviz(os, node->_t_right, "green");
		} else {
			os.write("-- {");

			if (node->_t_left)
				os.xprintf("\"%p\"", (const void *)node->_t_left);

			if (node->_t_right)
				os.xprintf(" \"%p\"", (const void *)node->_t_right);

			os.writeline("};");

			dump_internal_tree_graphviz(os, node->_t_left, 0);
			dump_internal_tree_graphviz(os, node->_t_right, 0);
		}
	}

	ptree_node *_a_child_black_node(ptree_node *node) const {
		if (node->_t_color == ptree_node::BLACK)
			return node;
		ptree_node *r = 0;
		if (node->_t_left)
			r = _a_child_black_node(node->_t_left);
		if (!r && node->_t_right)
			r = _a_child_black_node(node->_t_right);
		return r;
	}

	void _fix_parent(ptree_node *newnode, ptree_node *oldnode) {
		/* assert(oldnode); */
		/* assert(!oldnode->_t_parent
			|| oldnode->_t_parent->_t_right == oldnode
			|| oldnode->_t_parent->_t_left == oldnode); */

		if (!oldnode->_t_parent)
			head = newnode;
		else if (oldnode->_t_parent->_t_right == oldnode)
			oldnode->_t_parent->_t_right = newnode;
		else
			oldnode->_t_parent->_t_left = newnode;

		if (newnode)
			newnode->_t_parent = oldnode->_t_parent;
		oldnode->_t_parent = newnode;
	}

	void _pick_set_side(ptree_node *node, ptree_node *parent) {
		/* assert(node->_t_color == ptree_node::BLACK); */

		if (pnode_symbol_at(((node_type *)node)->prefix, parent->_t_bit))
			parent->_t_right = node;
		else
			parent->_t_left = node;
	}

	node_type *_get_first_black() const {
		if (head) {
			if (head->_t_color == node_type::BLACK)
				return (node_type *)head;

			const ptree_node *curr = head, *prev = 0;
			_increment(curr, prev);
			return (node_type *)curr;
		}

		return 0;
	}

	int _first_dif_bit(const key_type &p1, const key_type &p2, int st,
			   int end) const {
		for (; st < end && pnode_symbol_at(p1, st) == pnode_symbol_at(p2, st); st++);
		return st;
	}

	ptree_node *_alloc_white(int bit) {
		ptree_node *n = whites.request_obj();
		if (n) {
			n->_t_parent = 0;
			n->_t_left = 0;
			n->_t_right = 0;
			n->_t_color = ptree_node::WHITE;
			n->_t_bit = bit;
		}
		return n;
	}

	void _return_white(ptree_node *n) {
		whites.return_obj(n);
	}

	ptree_node *head;
	uint32_t count;

	allocator whites;
};

#endif


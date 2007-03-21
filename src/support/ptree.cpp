/*
 * Multicast Routing Daemon (MRD)
 *   ptree.cpp
 *
 * Copyright (C) 2007 - Hugo Santos
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

#include <mrd/support/ptree.h>

base_ptree::base_ptree()
	: head(NULL), count(0) {}

base_ptree::~base_ptree() {
	clear();
}

bool base_ptree::empty() const {
	return head == NULL;
}

uint32_t base_ptree::size() const {
	return count;
}

bool base_ptree::remove(ptree_node *node) {
	if (!head || !node || node->_t_color != ptree_node::BLACK)
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

void base_ptree::clear() {
	ptree_node *node = 0;

	/* By removing every black node we also trigger
	 * the removal of all white nodes */
	while ((node = _get_first_black())) {
		remove(node);
	}
}

ptree_node *base_ptree::get_parent_node(const ptree_node *n) const {
	if (!n)
		return 0;

	do {
		n = n->_t_parent;
	} while (n && n->_t_color == ptree_node::WHITE);

	return (ptree_node *)n;
}

base_ptree::iterator::iterator()
	: curr(NULL), prev(NULL) {}

base_ptree::iterator::iterator(ptree_node *c)
	: curr(c), prev(NULL) {}

base_ptree::iterator::iterator(const iterator &i)
	: curr(i.curr), prev(i.prev) {}

ptree_node *base_ptree::iterator::increment() {
	if (curr == NULL)
		return NULL;

	do {
		ptree_node *_prev = prev;
		prev = curr;

		if (_prev && _prev == curr->_t_left) {
			/* coming from left, go right, or up */
			if (curr->_t_right)
				curr = curr->_t_right;
			else
				curr = curr->_t_parent;
		} else if (_prev && _prev == curr->_t_right) {
			/* coming from right, go up */
			curr = curr->_t_parent;
		} else if (curr->_t_left) {
			curr = curr->_t_left;
		} else if (curr->_t_right) {
			curr = curr->_t_right;
		} else {
			curr = curr->_t_parent;
		}
	} while (curr && (prev->_t_parent == curr ||
			  curr->_t_color == ptree_node::WHITE));

	return curr;
}

ptree_node *base_ptree::_get_first_black() const {
	if (head) {
		if (head->_t_color == ptree_node::BLACK)
			return head;

		return iterator(head).increment();
	}

	return NULL;
}

ptree_node *base_ptree::_a_child_black_node(ptree_node *node) const {
	if (node->_t_color == ptree_node::BLACK)
		return node;

	ptree_node *res = NULL, *ch[2] = { node->_t_left, node->_t_right };

	for (int i = 0; i < 2 && res == NULL; i++) {
		if (ch[i] != NULL)
			res = _a_child_black_node(ch[i]);
	}

	return res;
}

void base_ptree::_fix_parent(ptree_node *newnode, ptree_node *oldnode) {
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

ptree_node *base_ptree::_alloc_white(int bit) {
	ptree_node *n = whites.request_obj();
	if (n == NULL)
		return NULL;

	n->_t_parent = 0;
	n->_t_left = 0;
	n->_t_right = 0;
	n->_t_color = ptree_node::WHITE;
	n->_t_bit = bit;

	return n;
}

void base_ptree::_return_white(ptree_node *n) {
	whites.return_obj(n);
}

void base_ptree::dump_internal_tree(base_stream &os) const {
	dump_internal_tree(os, head, "root");
}

void base_ptree::dump_internal_tree_graphviz(base_stream &os) const {
	os.writeline("graph ptree {");
	os.inc_level();
	dump_internal_tree_graphviz(os, head, "black");
	dump_internal_tree_graphviz(os, head, 0);
	os.dec_level();
	os.writeline("}");
}

void base_ptree::dump_internal_tree(base_stream &os, const ptree_node *node,
				    const char *desc) const {
	if (!node)
		return;
	os.xprintf("%s ", desc);
	if (node->_t_color == ptree_node::BLACK)
		write_prefix(os, node);
	else
		os.write("white");
	os.xprintf(" at %i", (int)node->_t_bit);
	os.newl();

	os.inc_level();

	dump_internal_tree(os, node->_t_left, "left");
	dump_internal_tree(os, node->_t_right, "right");

	os.dec_level();
}

void base_ptree::dump_internal_tree_graphviz(base_stream &os,
					     const ptree_node *node,
					     const char *color) const {
	if (!node)
		return;

	os.xprintf("\"%p\" ", (const void *)node);

	if (color) {
		os.write("[label=\"");
		if (node->_t_color == ptree_node::BLACK)
			write_prefix(os, node);
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


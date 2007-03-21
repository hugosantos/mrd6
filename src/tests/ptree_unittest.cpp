#define BOOST_AUTO_TEST_MAIN
#include <boost/test/auto_unit_test.hpp>

#include <vector>
#include <iostream>
using namespace std;

typedef pair<uint32_t, int> test_prefix;

int pnode_prefix_length(const test_prefix &p) {
	return p.second;
}

bool pnode_symbol_at(const test_prefix &p, int n) {
	return (p.first >> (31 - n)) & 0x1;
}

#include <mrd/log.h>

void stream_push_formated_type(base_stream &os, const test_prefix &p) {
	char tmp[32];
	snprintf(tmp, sizeof(tmp), "%x", p.first);
	os.xprintf("[%s / %i]", tmp, p.second);
}

ostream & operator << (ostream &os, const test_prefix &p) {
	return os << "[" << hex << p.first << " / " << dec << p.second << "]";
}

#include <mrd/support/ptree.h>

bool operator == (const test_prefix &p1, const test_prefix &p2) {
	return p1.first == p2.first && p1.second == p2.second;
}

struct test_node : ptree_node {
	test_node(const test_prefix &pfx) : prefix(pfx) {}
	test_node(const test_node &n) : prefix(n.prefix) {}

	test_prefix prefix;

	friend bool operator == (const test_node &n1, const test_node &n2) {
		return n1.prefix == n2.prefix;
	}
};

static void fill_nodes(vector<test_node> &nodes) {
	nodes.push_back(test_node(test_prefix(0xffff0000, 16)));
	nodes.push_back(test_node(test_prefix(0x7fff0000, 16)));
	nodes.push_back(test_node(test_prefix(0x7fff1230, 30)));
	nodes.push_back(test_node(test_prefix(0x7fff1231, 32)));
}

BOOST_AUTO_UNIT_TEST(ptree_test1) {
	ptree<test_prefix, test_node> p;
	BOOST_REQUIRE(p.size() == 0);

	vector<test_node> nodes;
	fill_nodes(nodes);

	size_t count = 0;
	for (vector<test_node>::iterator i = nodes.begin(); i != nodes.end(); ++i) {
		test_node *node = &(*i);
		BOOST_CHECK(p.insert(node) == node);
		++count;
		BOOST_CHECK(p.size() == count);
	}

	for (vector<test_node>::iterator i = nodes.begin(); i != nodes.end(); ++i) {
		test_node *node = &(*i);
		BOOST_CHECK(p.search(node->prefix) == node);
	}

	log_base log(NULL);
	BOOST_REQUIRE(log.check_startup());
	log.attach_node(new file_log_node(&log, "stderr", EVERYTHING, stderr));

	p.dump_internal_tree(log.current_context());

	p.clear();
	BOOST_REQUIRE(p.size() == 0);
}

BOOST_AUTO_UNIT_TEST(ptree_test2) {
	ptree<test_prefix, test_node> p;
	BOOST_REQUIRE(p.size() == 0);

	vector<test_node> nodes;
	fill_nodes(nodes);

	for (vector<test_node>::iterator i = nodes.begin(); i != nodes.end(); ++i)
		BOOST_REQUIRE(p.insert(&(*i)) != NULL);

	BOOST_CHECK(p.longest_match(test_prefix(0x00000000, 32)) == NULL);
	BOOST_CHECK(p.longest_match(test_prefix(0xfffe0000, 32)) == NULL);
	BOOST_CHECK(p.longest_match(test_prefix(0xffff0000, 32)) == &nodes[0]);
	BOOST_CHECK(p.longest_match(test_prefix(0xffff8000, 32)) == &nodes[0]);
	BOOST_CHECK(p.longest_match(test_prefix(0xffff1234, 32)) == &nodes[0]);
	BOOST_CHECK(p.longest_match(test_prefix(0x7fff1200, 32)) == &nodes[1]);
	BOOST_CHECK(p.longest_match(test_prefix(0x7fff1230, 32)) == &nodes[2]);
	BOOST_CHECK(p.longest_match(test_prefix(0x7fff1232, 32)) == &nodes[2]);
	BOOST_CHECK(p.longest_match(test_prefix(0x7fff1231, 32)) == &nodes[3]);

	p.clear();
	BOOST_REQUIRE(p.size() == 0);
}

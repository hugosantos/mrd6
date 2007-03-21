#define BOOST_AUTO_TEST_MAIN
#include <boost/test/auto_unit_test.hpp>

#include <mrd/support/ptree.h>

struct test_node : ptree_node {
	uint32_t prefix;
};

BOOST_AUTO_UNIT_TEST(ptree_test1) {
	ptree<uint32_t, test_node> p;

	BOOST_CHECK(p.size() == 0);
}

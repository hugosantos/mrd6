#define BOOST_AUTO_TEST_MAIN
#include <boost/test/auto_unit_test.hpp>

#include <mrd/mrib.h>

using namespace std;

class test_origin : public mrib_origin {
	const char *description() const { return "test"; }

	void return_prefix(mrib_def::prefix *p) {
		delete p;
	}
};

#define ADDR(str)	inet6_addr(string(str))
#define ANY		inet6_addr::any()

static void prepare_prefix(mrib_def::prefix *p) {
	p->nexthop = ADDR("2001::1");
	p->distance = 0;
	p->metric = 0;
	p->flags = 0;
	p->intf = NULL;
}

BOOST_AUTO_UNIT_TEST(mrib_test1) {
	mrib_def m(NULL);
	test_origin o;

	BOOST_REQUIRE(m.check_startup());

	mrib_def::prefix *p1 = new mrib_def::prefix(&o);
	prepare_prefix(p1);

	mrib_def::prefix *p2 = new mrib_def::prefix(&o);
	prepare_prefix(p2);

	inet6_addr pfx1(ADDR("2000::/3"));
	inet6_addr pfx2(ADDR("2000:123::/32"));

	BOOST_REQUIRE(m.install_prefix(pfx1, p1));
	BOOST_REQUIRE(m.install_prefix(pfx2, p2));

	BOOST_CHECK(m.get_prefix(pfx1, NULL) == p1);
	BOOST_CHECK(m.get_prefix(pfx1, &o) == p1);

	BOOST_CHECK(m.get_prefix(pfx2, NULL) == p2);
	BOOST_CHECK(m.get_prefix(pfx2, &o) == p2);

	BOOST_CHECK(m.prefix_lookup(ADDR("2001:124::1"), ANY) == p1);
	BOOST_CHECK(m.prefix_lookup(ADDR("2001:123::1"), ANY) == p2);
	BOOST_CHECK(m.prefix_lookup(ADDR("3000:"), ANY) == NULL);

	m.shutdown();
}

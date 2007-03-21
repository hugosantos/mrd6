#define BOOST_AUTO_TEST_MAIN
#include <boost/test/auto_unit_test.hpp>

#include <mrd/address.h>
#include <mrd/mrib.h>

using namespace std;

class test_origin : public mrib_origin {
	const char *description() const { return "test"; }

	void return_prefix(mrib_def::prefix *p) {
		delete p;
	}
};

static inet6_addr ADDR(const char *str) {
	return inet6_addr(string(str));
}

static inet6_addr ANY() {
	return inet6_addr::any();
}

static mrib_def::prefix *new_prefix(mrib_origin *o) {
	mrib_def::prefix *p = new mrib_def::prefix(o);
	p->nexthop = inet6_addr::any();
	p->distance = 0;
	p->metric = 0;
	p->flags = 0;
	p->intf = NULL;
	return p;
}

static void test1(mrib_def &m, test_origin &o,
		  const inet6_addr &pfx1, mrib_def::prefix *p1,
		  const inet6_addr &pfx2, mrib_def::prefix *p2) {
	BOOST_CHECK(m.get_prefix(pfx1, NULL) == p1);
	BOOST_CHECK(m.get_prefix(pfx1, &o) == p1);

	BOOST_CHECK(m.get_prefix(pfx2, NULL) == p2);
	BOOST_CHECK(m.get_prefix(pfx2, &o) == p2);

	BOOST_CHECK(m.prefix_lookup(ADDR("2001:124::1"), ANY()) == p1);
	BOOST_CHECK(m.prefix_lookup(ADDR("2001:123::1"), ANY()) == p2);
	BOOST_CHECK(m.prefix_lookup(ADDR("7000::"), ANY()) == NULL);
}

BOOST_AUTO_UNIT_TEST(mrib_test1) {
	mrib_def m(NULL);
	test_origin o;

	BOOST_REQUIRE(m.check_startup());

	mrib_def::prefix *p1 = new_prefix(&o);
	mrib_def::prefix *p2 = new_prefix(&o);

	inet6_addr pfx1(ADDR("2000::/3"));
	inet6_addr pfx2(ADDR("2001:123::/32"));

	BOOST_REQUIRE(m.install_prefix(pfx1, p1));
	BOOST_REQUIRE(m.install_prefix(pfx2, p2));

	test1(m, o, pfx1, p1, pfx2, p2);

	m.shutdown();
}

BOOST_AUTO_UNIT_TEST(mrib_test1_rev) {
	mrib_def m(NULL);
	test_origin o;

	BOOST_REQUIRE(m.check_startup());

	mrib_def::prefix *p1 = new_prefix(&o);
	mrib_def::prefix *p2 = new_prefix(&o);

	inet6_addr pfx1(ADDR("2000::/3"));
	inet6_addr pfx2(ADDR("2001:123::/32"));

	BOOST_REQUIRE(m.install_prefix(pfx2, p2));
	BOOST_REQUIRE(m.install_prefix(pfx1, p1));

	test1(m, o, pfx1, p1, pfx2, p2);

	m.shutdown();
}

#define BOOST_AUTO_TEST_MAIN
#include <boost/test/auto_unit_test.hpp>

#include <mrd/address.h>

BOOST_AUTO_UNIT_TEST(address_test1) {
	inet6_addr a0(std::string("::/0"));
	inet6_addr a1(std::string("::"));
	inet6_addr a2(std::string("2000::/3"));
	inet6_addr a3(std::string("2001:123:456::/3"));
	inet6_addr a4(std::string("2001::1"));
	inet6_addr a5(std::string("2002::/16"));

	BOOST_CHECK(a0 == inet6_addr::any());
	BOOST_CHECK(a1.addr == in6addr_any);
	BOOST_CHECK(a1.prefixlen == 128);
	BOOST_CHECK(a2.addr.s6_addr[0] == 0x20);
	BOOST_CHECK(a2.prefixlen == 3);

	a3.apply_prefixlen();

	BOOST_CHECK(a2 == a3);
	BOOST_CHECK(a0.matches(a4));
	BOOST_CHECK(a2.matches(a4));
	BOOST_CHECK(!a5.matches(a4));
}


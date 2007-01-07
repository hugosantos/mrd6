/*
 * Multicast Routing Daemon (MRD)
 *   zebra.cpp
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

#include <mrd/address.h>
#include <mrd/mrd.h>
#include <mrd/packet_buffer.h>
#include <mrd/rib.h>

#include <assert.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>

enum {
	ZEBRA_INTERFACE_ADD		= 1,
	ZEBRA_INTERFACE_DELETE,
	ZEBRA_INTERFACE_ADDRESS_ADD,
	ZEBRA_INTERFACE_ADDRESS_DELETE,
	ZEBRA_INTERFACE_UP,
	ZEBRA_INTERFACE_DOWN,
	ZEBRA_IPV4_ROUTE_ADD,
	ZEBRA_IPV4_ROUTE_DELETE,
	ZEBRA_IPV6_ROUTE_ADD,
	ZEBRA_IPV6_ROUTE_DELETE,
	ZEBRA_REDISTRIBUTE_ADD,
	ZEBRA_REDISTRIBUTE_DELETE,
	ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
	ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
	ZEBRA_IPV4_NEXTHOP_LOOKUP,
	ZEBRA_IPV6_NEXTHOP_LOOKUP,
	ZEBRA_IPV4_IMPORT_LOOKUP,
	ZEBRA_IPV6_IMPORT_LOOKUP,
	ZEBRA_INTERFACE_RENAME,
	ZEBRA_ROUTER_ID_ADD,
	ZEBRA_ROUTER_ID_DELETE,
	ZEBRA_ROUTER_ID_UPDATE,
	/* afi/safi independent messages */
	ZEBRA_ROUTE_ADD,
	ZEBRA_ROUTE_DELETE,
	ZEBRA_NEXTHOP_LOOKUP,
	ZEBRA_IMPORT_LOOKUP,
	ZEBRA_MAX
};

enum {
	ZEBRA_ROUTE_SYSTEM		= 0,
	ZEBRA_ROUTE_KERNEL,
	ZEBRA_ROUTE_CONNECT,
	ZEBRA_ROUTE_STATIC,
	ZEBRA_ROUTE_RIP,
	ZEBRA_ROUTE_RIPNG,
	ZEBRA_ROUTE_OSPF,
	ZEBRA_ROUTE_OSPF6,
	ZEBRA_ROUTE_ISIS,
	ZEBRA_ROUTE_BGP,
	ZEBRA_ROUTE_HSLS,
	ZEBRA_ROUTE_MAX
};

enum {
	ZAPI_MESSAGE_NEXTHOP	= 1,
	ZAPI_MESSAGE_IFINDEX	= 2,
	ZAPI_MESSAGE_DISTANCE	= 4,
	ZAPI_MESSAGE_METRIC	= 8,
};

enum {
	AFI_IP	= 1,
	AFI_IP6 = 2,
};

enum {
	SAFI_UNICAST	= 1,
	SAFI_MULTICAST	= 2,
};

enum {
	ZEBRA_KERNEL_DISTANCE_DEFAULT	= 0,
	ZEBRA_CONNECT_DISTANCE_DEFAULT	= 0,
	ZEBRA_STATIC_DISTANCE_DEFAULT	= 1,
	ZEBRA_RIP_DISTANCE_DEFAULT	= 120,
	ZEBRA_OSPF_DISTANCE_DEFAULT	= 110,
	ZEBRA_ISIS_DISTANCE_DEFAULT	= 115,
	ZEBRA_IBGP_DISTANCE_DEFAULT	= 200,
	ZEBRA_EBGP_DISTANCE_DEFAULT	= 20,
};

enum {
	ZEBRA_NEXTHOP_IFINDEX	= 1,
	ZEBRA_NEXTHOP_IFNAME	= 2,
	ZEBRA_NEXTHOP_IPV6	= 6,
	ZEBRA_NEXTHOP_IPV6_IFINDEX	= 7,
	ZEBRA_NEXTHOP_IPV6_IFNAME	= 8,
};

static const char *command_name[] = { 0,
	"ZEBRA_INTERFACE_ADD",
	"ZEBRA_INTERFACE_DELETE",
	"ZEBRA_INTERFACE_ADDRESS_ADD",
	"ZEBRA_INTERFACE_ADDRESS_DELETE",
	"ZEBRA_INTERFACE_UP",
	"ZEBRA_INTERFACE_DOWN",
	"ZEBRA_IPV4_ROUTE_ADD",
	"ZEBRA_IPV4_ROUTE_DELETE",
	"ZEBRA_IPV6_ROUTE_ADD",
	"ZEBRA_IPV6_ROUTE_DELETE",
	"ZEBRA_REDISTRIBUTE_ADD",
	"ZEBRA_REDISTRIBUTE_DELETE",
	"ZEBRA_REDISTRIBUTE_DEFAULT_ADD",
	"ZEBRA_REDISTRIBUTE_DEFAULT_DELETE",
	"ZEBRA_IPV4_NEXTHOP_LOOKUP",
	"ZEBRA_IPV6_NEXTHOP_LOOKUP",
	"ZEBRA_IPV4_IMPORT_LOOKUP",
	"ZEBRA_IPV6_IMPORT_LOOKUP",
	"ZEBRA_INTERFACE_RENAME",
	"ZEBRA_ROUTER_ID_ADD",
	"ZEBRA_ROUTER_ID_DELETE",
	"ZEBRA_ROUTER_ID_UPDATE",
	"ZEBRA_ROUTE_ADD",
	"ZEBRA_ROUTE_DELETE",
	"ZEBRA_NEXTHOP_LOOKUP",
	"ZEBRA_IMPORT_LOOKUP"
};

static int _zebra_type_to_distance(int type) {
	switch (type) {
	case ZEBRA_ROUTE_SYSTEM:
	case ZEBRA_ROUTE_KERNEL:
		return ZEBRA_KERNEL_DISTANCE_DEFAULT;
	case ZEBRA_ROUTE_CONNECT:
		return ZEBRA_CONNECT_DISTANCE_DEFAULT;
	case ZEBRA_ROUTE_STATIC:
		return ZEBRA_STATIC_DISTANCE_DEFAULT;
	case ZEBRA_ROUTE_RIP:
	case ZEBRA_ROUTE_RIPNG:
		return ZEBRA_RIP_DISTANCE_DEFAULT;
	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		return ZEBRA_OSPF_DISTANCE_DEFAULT;
	case ZEBRA_ROUTE_ISIS:
		return ZEBRA_ISIS_DISTANCE_DEFAULT;
	case ZEBRA_ROUTE_BGP:
		return ZEBRA_EBGP_DISTANCE_DEFAULT;
	default:
		return 1000;
	}
}

const int INTERFACE_NAMSIZ	= 20;

class zebra_rib;

class zebra_module : public mrd_module, public mrib_origin, public node {
public:
	zebra_module(mrd *, void *);

	bool check_startup();
	void shutdown();

	void return_prefix(mrib_def::prefix *);

	const char *description() const;

	void send_message(int);
	void redistribute_send(int, int);

	void interface_add_delete(int, int);
	void interface_address_add_delete(int, int);
	void interface_up_down(int, int);
	void route_add_delete(int, int);

	void data_available(uint32_t);
	void trigger_send();

	int check_message();
	void process_message();

	bool do_lookup(const in6_addr &addr, int &dev, in6_addr &nexthop);

	zebra_rib *zrib;

	socket0<zebra_module> zebra_sock;

	encoding_buffer ibuf, obuf;
};

static zebra_module *zebra = 0;

class zebra_rib : public rib_def {
public:
	bool lookup_prefix(const in6_addr &addr, lookup_result &res) const;

	void propagate_prefix(bool, int, const inet6_addr &, const in6_addr &,
			      int, int);
};

module_entry(zebra, zebra_module);

zebra_module::zebra_module(mrd *m, void *p)
	: mrd_module(m, p), node(m, "zebra"), zrib(0),
	  zebra_sock("zebra sock", this, std::mem_fun(&zebra_module::data_available)),
	  ibuf(4096), obuf(4096) {

	zebra = this;
	g_mrd->add_child(this);
}

const char *zebra_module::description() const {
	return "Zebra routing daemon interoperation";
}

bool zebra_module::check_startup() {
	if (!node::check_startup())
		return false;

	if (!ibuf.check_startup() || !obuf.check_startup())
		return false;

	zrib = new zebra_rib();
	if (!zrib)
		return false;

	if (!g_mrd->register_rib(zrib))
		return false;

	int sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0)
		return false;

	sockaddr_un zebraaddr;
	memset(&zebraaddr, 0, sizeof(sockaddr_un));

	zebraaddr.sun_family = PF_LOCAL;
	strcpy(zebraaddr.sun_path, "/var/run/quagga/zserv.api");

	if (connect(sock, (sockaddr *)&zebraaddr, sizeof(sockaddr_un)) < 0) {
		perror("connect()");
		close(sock);
		return false;
	}

	zebra_sock.register_fd(sock);

	send_message(ZEBRA_INTERFACE_ADD);

	redistribute_send(ZEBRA_REDISTRIBUTE_ADD, ZEBRA_ROUTE_SYSTEM);
	redistribute_send(ZEBRA_REDISTRIBUTE_ADD, ZEBRA_ROUTE_KERNEL);
	redistribute_send(ZEBRA_REDISTRIBUTE_ADD, ZEBRA_ROUTE_CONNECT);
	redistribute_send(ZEBRA_REDISTRIBUTE_ADD, ZEBRA_ROUTE_STATIC);
	redistribute_send(ZEBRA_REDISTRIBUTE_ADD, ZEBRA_ROUTE_RIPNG);
	redistribute_send(ZEBRA_REDISTRIBUTE_ADD, ZEBRA_ROUTE_OSPF6);
	redistribute_send(ZEBRA_REDISTRIBUTE_ADD, ZEBRA_ROUTE_BGP);

	return true;
}

void zebra_module::shutdown() {
}

void zebra_module::return_prefix(mrib_def::prefix *p) {
	delete p;
}

void zebra_module::send_message(int command) {
	obuf.put<uint16_t>() = htons(3);
	obuf.put<uint8_t>() = command;

	trigger_send();
}

void zebra_module::redistribute_send(int command, int id) {
	obuf.put<uint16_t>() = htons(4);
	obuf.put<uint8_t>() = command;
	obuf.put<uint8_t>() = id;

	trigger_send();
}

void zebra_module::data_available(uint32_t type) {
	if (type == socket_base::Write) {
		/* We can write, let's feed as much data as possible to zebra */
		obuf.flush_to(zebra_sock, true);
		return;
	}

	int len = ibuf.consume(zebra_sock);
	if (len <= 0)
		return;

	while (check_message() >= 0) {
		process_message();
	}
}

int zebra_module::check_message() {
	if (!ibuf.require(3))
		return -1;

	uint8_t *head = ibuf.head();

	int length = ntohs(*(uint16_t *)head);
	int command = head[2];

	/* zebra message isn't fully here yet */
	if (!ibuf.require(length)) {
		return -1;
	}

	return command;
}

void zebra_module::process_message() {
	uint8_t *head = ibuf.head();

	int length = ntohs(*(uint16_t *)head);
	int command = head[2];

	if (command == 0 || command >= ZEBRA_MAX) {
		/* unknown message, consume it */
		ibuf.eat(length);
		return;
	}

	ibuf.eat(3);
	length -= 3;

	if (should_log(DEBUG))
		log().xprintf("Zebra message %s length %i\n",
			      command_name[command], length);

	switch (command) {
	case ZEBRA_INTERFACE_ADD:
	case ZEBRA_INTERFACE_DELETE:
		interface_add_delete(command, length);
		break;
	case ZEBRA_INTERFACE_ADDRESS_ADD:
	case ZEBRA_INTERFACE_ADDRESS_DELETE:
		interface_address_add_delete(command, length);
		break;
	case ZEBRA_INTERFACE_UP:
	case ZEBRA_INTERFACE_DOWN:
		interface_up_down(command, length);
		break;
	case ZEBRA_IPV6_ROUTE_ADD:
	case ZEBRA_IPV6_ROUTE_DELETE:
		route_add_delete(command, length);
		break;
	case ZEBRA_ROUTE_ADD:
	case ZEBRA_ROUTE_DELETE:
		route_add_delete(command, length);
		break;
	default:
		ibuf.eat(length);
	}

	ibuf.compact();
}

void zebra_module::trigger_send() {
	if (!obuf.empty()) {
		zebra_sock.monitor(socket_base::Read | socket_base::Write);
		obuf.flush_to(zebra_sock, true);
	}
}

void zebra_module::interface_add_delete(int command, int length) {
	char name[INTERFACE_NAMSIZ+1];
	int index, status, flags, mtu;

	memcpy(name, ibuf.eat(INTERFACE_NAMSIZ), INTERFACE_NAMSIZ);
	name[INTERFACE_NAMSIZ] = 0;

	index = ibuf.neatl();

	status = ibuf.neatu8();
	flags = ibuf.neatl();
	/* metric = */ ibuf.neatl();
	mtu = ibuf.neatl();
	/* mtu6 = */ ibuf.neatl();

	/* bandwidth = */ ibuf.neatl();

	if (command == ZEBRA_INTERFACE_ADD) {
		int addrlen = ibuf.neatl();
		ibuf.eat(addrlen);

		interface *intf = g_mrd->found_interface(index, name, 0, mtu, flags);

		if (flags & IFF_UP) {
			intf->change_state(interface::Up);
		}
	} else {
		g_mrd->lost_interface(index);
	}
}

void zebra_module::interface_address_add_delete(int command, int length) {
	int index, flags, family;

	index = ibuf.neatl();
	flags = ibuf.neatu8();
	family = ibuf.neatu8();

	if (family == AF_INET) {
		/* we ignore IPv4 addresses */
		ibuf.eat(length - (4 + 1 + 1));
	} else {
		inet6_addr addr;

		memcpy(&addr.addr, ibuf.eat(16), 16);
		addr.prefixlen = ibuf.neatu8();

		in6_addr dest; /* ? */
		memcpy(&dest, ibuf.eat(16), 16);

		bool add = (command == ZEBRA_INTERFACE_ADDRESS_ADD);

		interface *intf = g_mrd->get_interface_by_index(index);
		if (intf)
			intf->address_added_or_removed(add, addr);
	}
}

void zebra_module::interface_up_down(int command, int length) {
	int index;

	ibuf.eat(INTERFACE_NAMSIZ);
	index = ibuf.neatl();
	/* status = */ ibuf.neatu8();
	/* flags = */ ibuf.neatl();
	/* metric = */ ibuf.neatl();
	/* mtu = */ ibuf.neatl();
	/* mtu6 = */ ibuf.neatl();
	/* bandwidth = */ ibuf.neatl();

	interface *intf = g_mrd->get_interface_by_index(index);
	if (intf) {
		if (command == ZEBRA_INTERFACE_UP) {
			intf->change_state(interface::Up);
		} else {
			intf->change_state(interface::Down);
		}
	}
}

void zebra_module::route_add_delete(int command, int length) {
	int afi = AFI_IP6, safi = SAFI_UNICAST;

	if (command == ZEBRA_ROUTE_ADD || command == ZEBRA_ROUTE_DELETE) {
		afi = ibuf.neatu16();
		safi = ibuf.neatu8();
	}

	bool add =    (command == ZEBRA_ROUTE_ADD)
		   || (command == ZEBRA_IPV6_ROUTE_ADD);

	int type, flags, msgflags;

	type = ibuf.neatu8();
	flags = ibuf.neatu8();
	msgflags = ibuf.neatu8();

	inet6_addr prefix;
	prefix.prefixlen = ibuf.neatu8();
	int blen = (prefix.prefixlen + 7) / 8;
	memcpy(&prefix.addr, ibuf.eat(blen), blen);

	int ifindex = 0;
	in6_addr nexthop = in6addr_any;
	int distance = 0, metric = 0;

	if (msgflags & ZAPI_MESSAGE_NEXTHOP) {
		int count = ibuf.neatu8();
		for (int i = 0; i < count; i++)
			memcpy(&nexthop, ibuf.eat(sizeof(in6_addr)),
			       sizeof(in6_addr));
	}

	if (msgflags & ZAPI_MESSAGE_IFINDEX) {
		int count = ibuf.neatu8();
		for (int i = 0; i < count; i++)
			ifindex = ibuf.neatl();
	}

	if (msgflags & ZAPI_MESSAGE_DISTANCE)
		distance = ibuf.neatu8();

	if (msgflags & ZAPI_MESSAGE_METRIC)
		metric = ibuf.neatl();

	if (type == ZEBRA_ROUTE_CONNECT) {
		/* we already handle directly connected prefixes */
		return;
	}

	if (safi == SAFI_UNICAST) {
		zrib->propagate_prefix(add, ifindex, prefix, nexthop,
				       _zebra_type_to_distance(type), metric);
	} else if (safi == SAFI_MULTICAST) {
		if (add) {
			mrib_def::prefix *p = new mrib_def::prefix(this);

			if (p) {
				p->distance = _zebra_type_to_distance(type);
				p->metric = metric;
				p->nexthop = nexthop;
				p->intf = g_mrd->get_interface_by_index(ifindex);
				p->flags = mrib_def::prefix::NO_EXPORT;

				g_mrd->mrib().install_prefix(prefix, p);
			}
		} else {
			mrib_def::prefix *p = g_mrd->mrib().get_prefix(prefix, this);
			if (p)
				g_mrd->mrib().remove_prefix(p);
		}
	}
}

bool zebra_module::do_lookup(const in6_addr &addr, int &dev, in6_addr &nexthop) {
	/* flush everything */
	while (!obuf.empty())
		obuf.flush_to(zebra_sock, true, true);

	obuf.put<uint16_t>() = htons(3 + sizeof(in6_addr));
	obuf.put<uint8_t>() = ZEBRA_IPV6_NEXTHOP_LOOKUP;

	memcpy(obuf.put(sizeof(in6_addr)), &addr, sizeof(in6_addr));

	while (!obuf.empty())
		obuf.flush_to(zebra_sock, true, true);

	while (1) {
		int len = ibuf.consume(zebra_sock, true);
		if (len <= 0)
			return false;

		int command;

		if ((command = zebra->check_message())
			== ZEBRA_IPV6_NEXTHOP_LOOKUP) {
			/* addr = */ ibuf.eat(sizeof(in6_addr));
			/* metric = */ ibuf.neatl();
			int nexthop_count = ibuf.neatu8();

			for (int i = 0; i < nexthop_count; i++) {
				int type = ibuf.neatu8();

				switch (type) {
				case ZEBRA_NEXTHOP_IPV6:
					memcpy(&nexthop, ibuf.eat(sizeof(in6_addr)),
					       sizeof(in6_addr));
					break;
				case ZEBRA_NEXTHOP_IPV6_IFINDEX:
				case ZEBRA_NEXTHOP_IPV6_IFNAME:
					memcpy(&nexthop, ibuf.eat(sizeof(in6_addr)),
					       sizeof(in6_addr));
					dev = ibuf.neatl();
					break;
				case ZEBRA_NEXTHOP_IFINDEX:
				case ZEBRA_NEXTHOP_IFNAME:
					dev = ibuf.neatl();
					break;
				}
			}

			if (nexthop_count > 0) {
				return true;
			} else {
				break;
			}
		} else {
			zebra->process_message();
		}
	}

	return false;
}

bool zebra_rib::lookup_prefix(const in6_addr &addr, lookup_result &res) const {
	res.dst = addr;
	res.source = in6addr_any; /* XXX */
	res.dev = -1;

	return zebra->do_lookup(addr, res.dev, res.nexthop);
}

void zebra_rib::propagate_prefix(bool add, int ifindex, const inet6_addr &prefix,
				 const in6_addr &nexthop, int protocol, int metric) {
	/* this function exists because zebra_module doesn't access lookup_result */
	lookup_result res;

	res.dev = ifindex;
	res.dst = prefix;
	res.nexthop = nexthop;
	res.protocol = protocol;
	res.metric = metric;

	prefix_changed(add, res);
}

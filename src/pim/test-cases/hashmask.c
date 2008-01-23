#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(int argc, char **argv)
{
	struct in6_addr in;
	char buf[64];
	int mask, i;

	inet_pton(AF_INET6, argv[1], &in);
	mask = atoi(argv[2]);

	if (mask < 128) {
		in.s6_addr[mask / 8] &= 0xff << (8 - mask % 8);
		for (i = (mask + 7) / 8; i < 16; i++)
			in.s6_addr[i] = 0;
	}

	printf("result: %s\n", inet_ntop(AF_INET6, &in, buf, sizeof(buf)));

	return 0;
}

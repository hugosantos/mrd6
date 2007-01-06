#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define MRD_SOCKET "/var/run/mrd6"

int main(int argc, char *argv[]) {
	int i, sock;
	struct sockaddr_un addr;
	char buf[256];
	int ptr;

	if (argc < 2) {
		printf("No command specified.\n");
		return -1;
	}

	strcpy(buf, argv[1]);
	ptr = strlen(buf);

	for (i = 2; i < argc; i++) {
		if ((ptr + strlen(argv[i])) >= sizeof(buf)) {
			printf("Command is too long.\n");
			return -1;
		}
		sprintf(buf + ptr, " %s", argv[i]);
		ptr += 1 + strlen(argv[i]);
	}

	buf[ptr] = 0;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket()");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, MRD_SOCKET);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect()");
		return -1;
	}

	if (send(sock, buf, ptr + 1, 0) < 0) {
		perror("send()");
		return -1;
	}

	while ((i = recv(sock, buf, sizeof(buf), 0)) > 0) {
		buf[i] = 0;
		printf(buf);
	}

	return 0;
}


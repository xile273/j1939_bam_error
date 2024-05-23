#include <stdio.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/j1939.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/kernel.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#define CAN_DEV "can0"
#define SLEEP_TIME_NS 5000000

int jt_create_sock()
{
    int ret;
	int err_queue = 1;
    int sock;
    unsigned int sock_opt;
		
    sock = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
	if (sock < 0) {
		printf("Error creating socket %m\n");
		return ret;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
			 &err_queue, sizeof(err_queue));
	if (ret < 0) {
		printf("Error setting broadcast opt %m\n");
		return ret;
	}

	return sock;
}

int jt_bind_socket(int sock, const char* if_name,  u_int64_t name, u_int32_t pgn, u_int8_t addr)
{
    int ret; 
    struct ifreq ifr = {};
    struct sockaddr_can sc = {};

    strcpy(ifr.ifr_name, if_name);
    ret = ioctl(sock, SIOCGIFINDEX, &ifr);

    if(ret < 0)
    {
        printf("Error SIOCGIFINDEX ioctl %m\n");
        return ret;
    }

    sc.can_family = AF_CAN;
    sc.can_ifindex = ifr.ifr_ifindex;
    sc.can_addr.j1939.addr = addr;
    sc.can_addr.j1939.name = name;
    sc.can_addr.j1939.pgn = pgn;

    ret = bind(sock, (struct sockaddr*) &sc, sizeof(sc));

    if(ret < 0)
    {
        printf("Error binding %m\n");
        return ret;
    }

    return 0;
}

int main()
{
    int sock = jt_create_sock();
    int ret;
	u_int8_t data[] = {0x10, 0x3F, 0x46, 0x00, 0x02, 0x22, 0xAB, 0x00, 0x02, 0x03, 0x10, 0xF7, 0xEC, 0x03, 0x6F, 0x00, 0x12,
						0x7E, 0x4B, 0xF7, 0xF2, 0x7E, 0x1A, 0xF7, 0xE4, 0x7E, 0x1A, 0xF7, 0xEB, 0x7E, 0x1A, 0xF7, 0xE6, 0x7E};
	const struct sockaddr_can saddr = {
		.can_family = AF_CAN,
		.can_addr.j1939 = {
				.name = J1939_NO_NAME,
				.pgn = 0xFECA,
				.addr = 0xFF,
		},
    };

	const struct timespec sleep_time = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_TIME_NS
	};

    if(sock < 0)
	{
        return -1;
    }

    ret = jt_bind_socket(sock, CAN_DEV, J1939_NO_NAME, J1939_NO_PGN, 0x27);

	if(ret < 0)
	{
		return -1;
	}

	printf("Make sure there is no other can device on the bus\n");
	printf("Press any button to continue\n");

	getc(stdin);
	printf("Sending a couple of messages\n");
	for(int i = 0; i < 1000; i++)
	{
		int res = sendto(sock, data, 5, 0, (const struct sockaddr *) &saddr, sizeof(saddr));
		if(res == -1)
		{
			printf("%m\n");
		}
		//clock_nanosleep(CLOCK_REALTIME, 0, &sleep_time, NULL);
	}
	printf("Switch on another device on the bus\n");
	printf("Press any button\n");
	getc(stdin);
	printf("Sending a couple of messages\n");
	for(int i = 0; i < 10; i++)
	{
		int res = sendto(sock, data, sizeof(data), 0, (const struct sockaddr *) &saddr, sizeof(saddr));
		if(res == -1)
			printf("%m\n");
		
		clock_nanosleep(CLOCK_REALTIME, 0, &sleep_time, NULL);
	}

	printf("Now closing socket....\n");
	close(sock);
	}

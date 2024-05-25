#include <stdio.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/j1939.h>
#include <linux/net_tstamp.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/kernel.h>
#include <linux/errqueue.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <time.h>

#define CAN_DEV "can0"
#define NS_IN_MS 1000000
#define SLEEP_TIME_MS 50
#define SLEEP_TIME_NS (SLEEP_TIME_MS * NS_IN_MS)
#define SLEEP_TIME_S 0

enum jt_prev_state {
    JT_PREV_SEND_SUCCESS = 1,
    JT_PREV_SEND_FAIL
};

struct jt_err_msg {
    struct sock_extended_err *serr;
    struct scm_timestamping *tss;
};

struct jt_err_thread_args
{
    volatile int running;
    int sock;
    int efd;
};


volatile enum jt_prev_state prev_state  = JT_PREV_SEND_SUCCESS;

struct timespec diff_timespec(const struct timespec *time1,
    const struct timespec *time0) {

  struct timespec diff = {.tv_sec = time1->tv_sec - time0->tv_sec, //
      .tv_nsec = time1->tv_nsec - time0->tv_nsec};
  if (diff.tv_nsec < 0) {
    diff.tv_nsec += 1000000000; // nsec/sec
    diff.tv_sec--;
  }
  return diff;
}

static int jt_parse_cm(struct jt_err_msg *emsg,
                 struct cmsghdr *cm)
{
    const size_t hdr_len = CMSG_ALIGN(sizeof(struct cmsghdr));

    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING) {
        emsg->tss = (void *)CMSG_DATA(cm);
    }
    else if(cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING_OPT_STATS)
    {
        int offset = 0;
        int len = cm->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr));

        while(offset < len) {
            struct nlattr* nla = (struct nlattr*) ((char*) CMSG_DATA(cm) + offset);

            switch(nla->nla_type) {
                case J1939_NLA_BYTES_ACKED:
                    break;
                default:
                    printf("Non sup NLA field\n");
            }

            offset += NLA_ALIGN(nla->nla_len);
        }
    }
    else if (cm->cmsg_level == SOL_CAN_J1939 &&
           cm->cmsg_type == SCM_J1939_ERRQUEUE) {
        emsg->serr = (void *)CMSG_DATA(cm);
    }
    else
    {
        printf("Non supported cmsg type: %d.%d\n",
              cm->cmsg_level, cm->cmsg_type);
    }

    return 0;
}

int jt_create_sock()
{
    int ret;
    int err_queue = 1;
    int sock;
    unsigned int sock_opt;
        
    ret = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
    if (ret < 0) {
        printf("Error creating socket %m\n");
        return ret;
    }

    sock = ret;

    ret = setsockopt(sock, SOL_CAN_J1939, SO_J1939_ERRQUEUE,
             &err_queue, sizeof(err_queue));
    if (ret < 0) {
        printf("Error setting errqueue opt %m\n");
        return ret;
    }


    sock_opt = SOF_TIMESTAMPING_SOFTWARE  |
           SOF_TIMESTAMPING_TX_ACK | SOF_TIMESTAMPING_TX_SCHED  |
           SOF_TIMESTAMPING_OPT_ID;

    ret = setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING,
                     (char *)&sock_opt, sizeof(sock_opt));
    if (ret < 0) {
        printf("Error setting timestamp %m\n");
        return ret;
    }

    ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &err_queue, sizeof(err_queue));
    if (ret < 0) {
        printf("Error setting so broadcast %m\n");
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

static enum jt_prev_state jt_extract_serr(struct jt_err_msg *emsg)
{
    enum jt_prev_state res = JT_PREV_SEND_SUCCESS;
    struct sock_extended_err *serr = emsg->serr;
    struct scm_timestamping *tss = emsg->tss;

    switch (serr->ee_origin) {
    case SO_EE_ORIGIN_TIMESTAMPING:
        /*
         * We expect here following patterns:
         *   serr->ee_info == SCM_TSTAMP_ACK
         *     Activated with SOF_TIMESTAMPING_TX_ACK
         * or
         *   serr->ee_info == SCM_TSTAMP_SCHED
         *     Activated with SOF_TIMESTAMPING_SCHED
         * and
         *   serr->ee_data == tskey
         *     session message counter which is activate
         *     with SOF_TIMESTAMPING_OPT_ID
         * the serr->ee_errno should be ENOMSG
         */
        if (serr->ee_errno != ENOMSG)
            printf("serr: expected ENOMSG, got: %i\n",
                  serr->ee_errno);

        switch(serr->ee_info)
        {
            case SCM_TSTAMP_ACK:
                printf("Got SCM_TSAMP_ACK at sn %d\n", serr->ee_data);
                res = JT_PREV_SEND_SUCCESS;
                break;
            case SCM_TSTAMP_SCHED:
                printf("Got SCM_TSAMP_SCHED at sn %d\n", serr->ee_data);
                break;
            default:
                printf("Got unknown tsampt type %d at sn %d\n", serr->ee_info, serr->ee_data);
            

        }

    case SO_EE_ORIGIN_LOCAL:
        /*
         * The serr->ee_origin == SO_EE_ORIGIN_LOCAL is
         * currently used to notify about locally
         * detected protocol/stack errors.
         * Following patterns are expected:
         *   serr->ee_info == J1939_EE_INFO_TX_ABORT
         *     is used to notify about session TX
         *     abort.
         *   serr->ee_data == tskey
         *     session message counter which is activate
         *     with SOF_TIMESTAMPING_OPT_ID
         *   serr->ee_errno == actual error reason
         *     error reason is converted from J1939
         *     abort to linux error name space.
         */
        switch(serr->ee_info)
        {
            case J1939_EE_INFO_NONE:
                printf("Got INFO_NONE for session %d\n", serr->ee_data);
                break;
            case J1939_EE_INFO_TX_ABORT:
                printf("Got INFO_TX_ABORT for sn %d\n", serr->ee_data);
                res = JT_PREV_SEND_FAIL;
                break;
            case J1939_EE_INFO_RX_RTS:
                printf("Got J1939_EE_INFO_RX_RTS for sn %d\n", serr->ee_data);
                break;
            default:
                printf("Got unknown ee_info %d\n", serr->ee_info);

        }
        break;
    default:
        printf("serr: wrong origin: %u\n", serr->ee_origin);
    }

    return res;
}

enum jt_prev_state jt_read_error_queue(int sock, struct jt_err_msg* emsg)
{
    char control[200];
    struct cmsghdr *cm;
    int ret;

    struct  pollfd pfd =
    {
        .fd = sock
    };
    

    struct msghdr msg = {
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };

    ret = poll(&pfd, 1, -1);
    if(ret && (pfd.revents & POLLERR))
    {
        ret = recvmsg(sock, &msg, MSG_ERRQUEUE);
        if (ret == -1) {
            printf("recmsg %m\n");
            return 0;
        }

        if (msg.msg_flags & MSG_CTRUNC) {
            printf("recvmsg error notification: truncated\n");
            return 0;
        }

        emsg->serr = NULL;
        emsg->tss = NULL;

        for (cm = CMSG_FIRSTHDR(&msg); cm && cm->cmsg_len;
            cm = CMSG_NXTHDR(&msg, cm)) {
            jt_parse_cm(emsg, cm);
            if (emsg->serr && emsg->tss)
                return jt_extract_serr(emsg);
        }
    }

    return 0;
}

void* err_thread(void* args)
{
    struct jt_err_msg err;
    struct jt_err_thread_args* err_args = args;

    printf("Err thread starting\n");


    while(err_args->running)
    {
        uint64_t res = jt_read_error_queue(err_args->sock, &err );
        prev_state = res;
        res = 1;
        //printf("Allowing next send\n");
        write(err_args->efd, &res, sizeof(res));
    }

    printf("Err thread returning\n");

    return NULL;
}

int main()
{
    int sock = jt_create_sock();
    int ret;
    struct  jt_err_thread_args targs =
    {
        .running = 1,
        .sock = sock,
        .efd = eventfd(0, 0)
    };
    pthread_t err_thread_handle;
    u_int8_t data[] = {0x10, 0x3F, 0x46, 0x00, 0x02, 0x22, 0xAB, 0x00, 0x02, 0x03, 0x10, 0xF7, 0xEC, 0x03, 0x6F, 0x00, 0x12,
                        0x7E, 0x4B, 0xF7, 0xF2, 0x7E, 0x1A, 0xF7, 0xE4, 0x7E, 0x1A, 0xF7, 0xEB, 0x7E, 0x1A, 0xF7, 0xE6, 0x7E};
    const struct sockaddr_can saddr = {
        .can_family = AF_CAN,
        .can_addr.j1939 = {
                .name = J1939_NO_NAME,
                .pgn = 0x00FECA,
                .addr = 0xFF,
        },
    };

    struct timespec sleep_time = {.tv_sec = SLEEP_TIME_S, .tv_nsec = SLEEP_TIME_NS};


    if(sock < 0) {
        return -1;
    }

    ret = jt_bind_socket(sock, "can0", J1939_NO_NAME, J1939_NO_PGN, 0x27);
    if(ret < 0) {
        return -1;
    }

    pthread_create(&err_thread_handle, 0, err_thread, &targs);


    printf("Make sure there is no other can device on the bus\n");
    printf("Press any button to continue\n");

    getc(stdin);
    printf("Sending a couple of messages\n");
    for(int i = 0; i < 50; i++)
    {
        int res;

        printf("Sending sn %d\n", i);
        res= sendto(sock, data, sizeof(data), 0, (const struct sockaddr *) &saddr, sizeof(saddr));
        if(res == -1)
        {
            printf("Got error: %m. continuing...\n");
        }
        clock_nanosleep(CLOCK_REALTIME, 0, &sleep_time, NULL);
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

    close(sock);

    printf("Closing socket\n");
    close(sock);
    printf("Closed socket\n");
    targs.running = 0;

    printf("Waiting a bit to print more error messages\n");
    sleep(100);

    return 0;

}

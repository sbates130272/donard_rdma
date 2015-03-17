////////////////////////////////////////////////////////////////////////
//
// Copyright 2014 PMC-Sierra, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License. You may
// obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0 Unless required by
// applicable law or agreed to in writing, software distributed under the
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for
// the specific language governing permissions and limitations under the
// License.
//
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
//
//   Author: Logan Gunthorpe
//
//   Date:   Oct 23 2014
//
//   Description:
//     RDMA Test Server
//
////////////////////////////////////////////////////////////////////////

#include "common.h"
#include "version.h"

#include <argconfig/argconfig.h>
#include <argconfig/suffix.h>

#ifdef HAVE_DONARD_PINPOOL_H
#include <donard/pinpool.h>
#endif

#include <rdma/rdma_verbs.h>

#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>


const char program_desc[] =
    "RDMA test server for moving data to GPU memory";

struct config {
    unsigned pbuf_size_mb;
    unsigned buf_size;
    int use_gpu_mem;
    int send_recv_dis;
    char *listen_port;
    char *mmap_file;
    unsigned mmap_offset;
    int show_version;
    int one_time;
    int force_mem;
};

static const struct config defaults = {
    .pbuf_size_mb = 1,
    .use_gpu_mem = 0,
    .listen_port = "11935",
};

static const struct argconfig_commandline_options command_line_options[] = {
    {"b",             "NUM", CFG_POSITIVE, NULL, required_argument, NULL},
    {"bufsize",       "NUM", CFG_POSITIVE, &defaults.pbuf_size_mb, required_argument,
            "pin buffer size (in MB)"},
    {"g",               "", CFG_NONE, &defaults.use_gpu_mem, no_argument, NULL},
    {"gpu",             "", CFG_NONE, &defaults.use_gpu_mem, no_argument,
#ifdef HAVE_DONARD_PINPOOL_H
            "RDMA directly to/from a buffer in gpu memory"},
#else
            "RDMA directly to/from a buffer in gpu memory -- not supported (requires libdonard)"},
#endif
    {"s",       "",          CFG_NONE, &defaults.send_recv_dis, no_argument, NULL},
    {"send-recv_dis",    "", CFG_NONE, &defaults.send_recv_dis, no_argument,
            "disable send/recv test"},
    {"m",             "FILE", CFG_STRING, NULL, required_argument, NULL},
    {"mmap",          "FILE", CFG_STRING, &defaults.mmap_file, required_argument,
            "use a buffer mmaped from the specified file"},
    {"o",             "NUM", CFG_POSITIVE, NULL, required_argument, NULL},
    {"offset",        "NUM", CFG_POSITIVE, &defaults.mmap_offset, required_argument,
            "offset within the mmaped buffer"},
    {"p",             "PORT", CFG_STRING, &defaults.listen_port, required_argument, NULL},
    {"port",          "PORT", CFG_STRING, &defaults.listen_port, required_argument,
            "port for the server to listen on"},
    {"t",               "", CFG_NONE, &defaults.one_time, no_argument, NULL},
    {"one-time",        "", CFG_NONE, &defaults.one_time, no_argument,
            "quit the server after servicing a single request"},
    {"f",               "", CFG_NONE, &defaults.force_mem, no_argument, NULL},
    {"force-mem",       "", CFG_NONE, &defaults.force_mem, no_argument,
            "attempt to force the memory lock to bufsize"},
    {"V",               "", CFG_NONE, &defaults.show_version, no_argument, NULL},
    {"version",         "", CFG_NONE, &defaults.show_version, no_argument,
                        "print the version and exit"},
    {0}
};


struct buffer {
    int fd;
    struct pin_buf *pbuf;
    size_t buf_size;
    void *addr;
    struct ibv_mr *mr;
};


int create_buffer(struct buffer *b, struct rdma_cm_id *id, struct config *cfg)
{
    struct timeval start_time, end_time;
    b->fd = -1;
    b->pbuf = NULL;
    gettimeofday(&start_time, NULL);

    if (cfg->mmap_file != NULL) {
        b->fd = open(cfg->mmap_file, O_RDWR);
        if (b->fd < 0) {
            fprintf(stderr, "cannot map file: %s: %s\n", cfg->mmap_file,
                    strerror(errno));
            return -1;
        }

        b->buf_size = cfg->buf_size;
        b->addr = mmap(NULL, cfg->buf_size, PROT_WRITE | PROT_READ,
                       MAP_SHARED, b->fd, cfg->mmap_offset);
        if (b->addr == MAP_FAILED) {
            perror("mmap failed");
            return -1;
        }
    } else if (cfg->use_gpu_mem) {
        #ifdef HAVE_DONARD_PINPOOL_H
        b->pbuf = pinpool_alloc();
        if (b->pbuf == NULL) {
            perror("pinpool_alloc");
            return -1;
        }

        b->addr = pinpool_mmap(b->pbuf);
        b->buf_size = b->pbuf->bufsize;
        #else
        return -1;
        #endif
    } else {
        b->buf_size = cfg->buf_size;
        b->addr = malloc(cfg->buf_size);
        if (b->addr == NULL) {
            perror("could not allocate buffer");
            return -2;
        }
    }

    b->mr = ibv_reg_mr(id->pd, b->addr, b->buf_size,
                       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                       IBV_ACCESS_REMOTE_READ);
    if (!b->mr) {
        fprintf(stderr, "rdma_reg_msgs/read: %d  ", errno);
        return -3;
    }
    gettimeofday(&end_time, NULL);
    double create_time = (double)elapsed_utime(start_time,
                                               end_time)/1e6;
    const char *create_suffix = suffix_dbinary_get(&create_time);
    fprintf(stdout,"Buffer Creation Time: %3.1f %2ss\n", create_time,
        create_suffix);

    return 0;
}

void destroy_buffer(struct buffer *b)
{
    //NB: In an actual implementation, it would probably be a good idea to
    // zero the GPU buffer otherwise it would leak into the next client
    // connection.
    rdma_dereg_mr(b->mr);

    if (b->fd >= 0) {
        munmap(b->addr, b->buf_size);
        close(b->fd);
    } else if (b->pbuf != NULL) {
        #ifdef HAVE_DONARD_PINPOOL_H
        pinpool_free(b->pbuf);
        #endif
    } else {
        free(b->addr);
    }
}

struct rdma_cm_id *setup_server(struct config *cfg)
{
    struct rdma_addrinfo hints, *res;
    struct ibv_qp_init_attr attr;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags = RAI_PASSIVE;
    hints.ai_port_space = RDMA_PS_TCP;
    if (rdma_getaddrinfo(NULL, cfg->listen_port, &hints, &res)) {
        perror("rdma_getaddrinfo");
        return NULL;
    }

    struct rdma_cm_id *listen_id;

    memset(&attr, 0, sizeof attr);
    attr.cap.max_send_wr = attr.cap.max_recv_wr = 8;
    attr.cap.max_send_sge = attr.cap.max_recv_sge = 8;
    attr.cap.max_inline_data = 16;
    attr.sq_sig_all = 1;
    if (rdma_create_ep(&listen_id, res, NULL, &attr)) {
        perror("rdma_create_ep");
        return NULL;
    }

    if (rdma_listen(listen_id, 0)) {
        perror("rdma_listen");
        return NULL;
    }

    return listen_id;
}

static char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                  s, maxlen);
        break;

    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                  s, maxlen);
        break;

    default:
        strncpy(s, "Unknown AF", maxlen);
        return NULL;
    }

    return s;
}

static int check_random_data(unsigned int seed, uint32_t *buf, size_t length, int use_zeros)
{
    uint32_t var;
    srand(seed);
    for (int i = 0; i < length / sizeof(*buf); i++) {
        var = (use_zeros) ? 0 : rand();
        if (buf[i] != var)
            return -1;
    }

    return 0;
}

static void wait_for_seed(struct rdma_cm_id *id, void *buf)
{
    struct ibv_wc wc;

    struct common_seed_data seed_data;
    struct ibv_mr *mr = rdma_reg_msgs(id, &seed_data, sizeof(seed_data));

    if (rdma_post_recv(id, NULL, &seed_data, sizeof(seed_data), mr)) {
        perror("rdma_post_recv");
        goto dereg_and_exit;
    }

    if (rdma_get_recv_comp(id, &wc) <= 0){
        perror("rdma_get_recv_comp");
        goto dereg_and_exit;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Recv Completion reported failure: %s (%d)\n",
                ibv_wc_status_str(wc.status), wc.status);
        goto dereg_and_exit;
    }

    printf("Got Seed %d, length %zd, use_zeros %d\n", seed_data.seed, seed_data.length,
           seed_data.use_zeros);

    if (!seed_data.length)
        goto dereg_and_exit;

    if (!check_random_data(seed_data.seed, buf, seed_data.length, seed_data.use_zeros))
        printf("Buffer Matches Random Seed.\n");
    else
        printf("ERROR: Buffer did not match random seed!\n");

dereg_and_exit:
    rdma_dereg_mr(mr);
}

static void send_goahead(struct rdma_cm_id *id, uint32_t *buf,
                         struct ibv_mr *mr)
{
    struct ibv_wc wc;

    if (rdma_post_send(id, NULL, buf, 0, mr, 0)) {
        perror("rdma_post_send");
        return;
    }

    if (rdma_get_send_comp(id, &wc) <= 0){
        perror("rdma_get_send_comp");
        return;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Send Completion reported failure: %s (%d)\n",
                ibv_wc_status_str(wc.status), wc.status);
        return;
    }

    printf("GoAhead Completed Successfully.\n");
}

int main(int argc, char *argv[])
{
    struct config cfg;
    int ret = 0;

    argconfig_parse(argc, argv, program_desc, command_line_options,
                    &defaults, &cfg, sizeof(cfg));

    if (cfg.show_version) {
        printf("Donard RDMA Server version %s\n", VERSION);
        return 0;
    }

    if (cfg.use_gpu_mem && !cfg.mmap_file) {
        #ifdef HAVE_DONARD_PINPOOL_H
        printf("Buffer Type: GPU\n");
        if (pinpool_init(1, cfg.pbuf_size_mb*1024*1024)) {
            perror("Could not initialize pin pool");
            return -1;
        }
        #else
        fprintf(stderr, "Not compiled with support for GPU buffers! "
                "Requires linking against libdonard\n");
        return -1;
        #endif
    } else if (!cfg.mmap_file) {
        printf("Buffer Type: CPU\n");
        cfg.buf_size = cfg.pbuf_size_mb*1024*1024;

        struct rlimit memlock_lim;
        getrlimit(RLIMIT_MEMLOCK, &memlock_lim);
        if (cfg.buf_size > memlock_lim.rlim_cur) {
            if (cfg.force_mem)
            {
                memlock_lim.rlim_max = memlock_lim.rlim_cur = cfg.buf_size;
                if(setrlimit(RLIMIT_MEMLOCK,&memlock_lim)){
                    fprintf(stderr, "cannot set MEMLOCK to %dMiB: %s\n", cfg.pbuf_size_mb,
                            strerror(errno));
                    return -1;
                }
            }
            else
                cfg.buf_size = memlock_lim.rlim_cur;
            fprintf(stderr, "Warning: Using a buffer size of %dMiB\n",
                    cfg.buf_size/1024/1024);

        }
    } else {
        printf("Buffer Type: MMAP\n");
        cfg.buf_size = cfg.pbuf_size_mb*1024*1024;
    }

    double buf_size       = cfg.buf_size;
    const char *bs_suffix = suffix_dbinary_get(&buf_size);
    printf("Buffer Size: %3.1f %2sB\n", buf_size, bs_suffix);

    struct rdma_cm_id *listen_id = setup_server(&cfg);
    if (listen_id == NULL)
        goto leave;

    printf("Listening on port %s\n", cfg.listen_port);

    while(1) {
        printf("\n");
        struct rdma_cm_id *id;

        if (rdma_get_request(listen_id, &id)) {
            perror("rdma_get_request");
            goto leave;
        }

        struct buffer b;
        if (create_buffer(&b, id, &cfg)) {
            perror("create_buffer");
            goto leave;
        }

        struct common_priv_data priv_data = {
            .buffer_addr = (uint64_t) b.addr,
            .buffer_rkey = b.mr->rkey,
            .buffer_length = b.mr->length,
        };

        printf("Buffer Created: 0x%" PRIx64 " length %zdkB\n",
               priv_data.buffer_addr, priv_data.buffer_length/1024);

        struct rdma_conn_param conn_param;
        memset(&conn_param, 0, sizeof(conn_param));
        conn_param.private_data_len = sizeof(priv_data);
        conn_param.private_data = &priv_data;
        conn_param.responder_resources = 2;
        conn_param.initiator_depth = 2;
        conn_param.retry_count = 5;
        conn_param.rnr_retry_count = 5;

        char peer_addr[60];
        get_ip_str(rdma_get_peer_addr(id), peer_addr, sizeof(peer_addr));

        printf("Accepting Client Connection: %s\n", peer_addr);
        if (rdma_accept(id, &conn_param)) {
            perror("rdma_accept");
            goto disconnect;
        }

        if (!cfg.send_recv_dis)
        {
            printf("Testing Send/Recv\n");
            common_test_send(id, b.addr, b.mr, COMMON_A1, COMMON_B1);
            common_test_recv(id, b.addr, b.mr, COMMON_A2, COMMON_B2);
            send_goahead(id, b.addr, b.mr);
        }
        wait_for_seed(id, b.addr);

        while (1) {
            struct rdma_cm_event *event;
            if (rdma_get_cm_event(id->channel, &event))
                goto disconnect;

            switch (event->event) {
            case RDMA_CM_EVENT_DISCONNECTED:
                printf("Client Disconnected.\n");
                rdma_ack_cm_event(event);
                goto disconnect;
            default:
                printf("Event: %s\n", rdma_event_str(event->event));
                break;
            }

            rdma_ack_cm_event(event);
        }

disconnect:
        rdma_disconnect(id);
        destroy_buffer(&b);
        if (cfg.one_time)
            goto leave;
    }


leave:
    #ifdef HAVE_DONARD_PINPOOL_H
    if (cfg.use_gpu_mem && !cfg.mmap_file) {
        pinpool_deinit();
    }
    #endif

    return ret;
}

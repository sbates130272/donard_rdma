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
//     RDMA Test Client
//
////////////////////////////////////////////////////////////////////////

#include "common.h"
#include "version.h"

#include <argconfig/argconfig.h>
#include <argconfig/report.h>
#include <argconfig/suffix.h>

#include <rdma/rdma_verbs.h>

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

const char program_desc[] =
    "RDMA test client for moving data to GPU memory";

struct config {
    char *addr;
    char *port;
    int verbose;
    int latency;
    long block_size;
    long count;
    unsigned nctxs;
    int send_recv_dis;
    int write_only;
    int read_only;
    int use_zeros;
    int show_version;
};

static const struct config defaults = {
    .addr = "127.0.0.1",
    .port = "11935",
    .block_size = 32768,
    .count = 8 << 20,
    .nctxs = 1,
};

static const struct argconfig_commandline_options command_line_options[] = {
    {"a",             "PORT", CFG_STRING, &defaults.addr, required_argument, NULL},
    {"addr",          "PORT", CFG_STRING, &defaults.addr, required_argument,
            "server address to connect to"},
    {"b",             "NUM", CFG_LONG_SUFFIX, &defaults.block_size, required_argument, NULL},
    {"block_size",    "NUM", CFG_LONG_SUFFIX, &defaults.block_size, required_argument,
            "block size to write with"},
    {"c",             "NUM", CFG_POSITIVE, &defaults.nctxs, required_argument, NULL},
    {"ctxs",          "NUM", CFG_POSITIVE, &defaults.nctxs, required_argument,
            "number of concurent contexts to run at once"},
    {"n",             "NUM", CFG_LONG_SUFFIX, &defaults.count, required_argument, NULL},
    {"length",        "NUM", CFG_LONG_SUFFIX, &defaults.count, required_argument,
            "total size of data to transfer per context"},
    {"p",             "PORT", CFG_STRING, &defaults.port, required_argument, NULL},
    {"port",          "PORT", CFG_STRING, &defaults.port, required_argument,
            "server port to connect to"},
    {"s",       "",          CFG_NONE, &defaults.send_recv_dis, no_argument, NULL},
    {"send-recv_dis",    "", CFG_NONE, &defaults.send_recv_dis, no_argument,
            "disable send/recv test"},
    {"r",       "", CFG_NONE, &defaults.read_only, no_argument, NULL},
    {"read",    "", CFG_NONE, &defaults.read_only, no_argument,
            "read only"},
    {"w",       "", CFG_NONE, &defaults.write_only, no_argument, NULL},
    {"write",   "", CFG_NONE, &defaults.write_only, no_argument,
            "write only"},
    {"z",           "", CFG_NONE, &defaults.use_zeros, no_argument, NULL},
    {"use_zeros",   "", CFG_NONE, &defaults.use_zeros, no_argument,
            "use zeros instead of random data (faster but riskier)"},
    {"v",             "", CFG_NONE, &defaults.verbose, no_argument, NULL},
    {"verbose",       "", CFG_NONE, &defaults.verbose, no_argument,
            "be verbose"},
    {"l",             "", CFG_NONE, &defaults.latency, no_argument, NULL},
    {"latency",       "", CFG_NONE, &defaults.latency, no_argument,
            "perform latency measurements"},
    {"V",               "", CFG_NONE, &defaults.show_version, no_argument, NULL},
    {"version",         "", CFG_NONE, &defaults.show_version, no_argument,
            "print the version and exit"},
    {0}
};

struct rdma_cm_id *do_connect(struct config *cfg)
{
    struct rdma_cm_id *id;
    struct rdma_addrinfo hints, *res;
    struct ibv_qp_init_attr attr;

    memset(&hints, 0, sizeof hints);
    hints.ai_port_space = RDMA_PS_TCP;
    if (rdma_getaddrinfo(cfg->addr, cfg->port, &hints, &res)) {
        perror("rdma_getaddrinfo");
        return NULL;
    }

    memset(&attr, 0, sizeof attr);
    attr.cap.max_send_wr = attr.cap.max_recv_wr = 16;
    attr.cap.max_send_sge = attr.cap.max_recv_sge = 16;
    attr.cap.max_inline_data = 0;
    attr.qp_context = id;
    attr.sq_sig_all = 1;
    int ret = rdma_create_ep(&id, res, NULL, &attr);
    rdma_freeaddrinfo(res);
    if (ret) {
        perror("rdma_create_ep");
        return NULL;
    }

    if (rdma_connect(id, NULL)) {
        perror("rdma_connect");
        return NULL;
    }

    return id;
}

struct remote_loc {
    uint32_t *start, *end, *cur;
    uint32_t rkey;
};

struct context {
    int idx;
    uint32_t *buf;
    size_t buf_len, elem;
    struct ibv_mr *mr;
    struct remote_loc *rloc;
    struct rdma_cm_id *id;

    int verbose;

    struct timeval start_time;

    unsigned int cur_seed;
    int use_zeros;

    unsigned int first_seed;

    uint32_t *readback_addr;
    size_t readback_len;

    unsigned long long wrote_bytes;
    unsigned long long read_bytes;
    unsigned long long latency;
    unsigned long long latency_min;
    unsigned long long latency_max;

    unsigned long count;
};

static struct context *init_context(struct rdma_cm_id *id, size_t buf_length,
                                    struct config *cfg, uint64_t rstart,
                                    uint64_t rend, uint32_t rkey)
{
    static int idx = 0;

    struct context *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->idx = idx++;
    ctx->verbose = cfg->verbose;
    ctx->buf_len = buf_length;
    ctx->elem = buf_length / sizeof(*ctx->buf);
    ctx->buf = malloc(buf_length*2);
    if (ctx->buf == NULL)
        goto free_ctx_out;

    ctx->mr = ibv_reg_mr(id->pd, ctx->buf, buf_length*2,
                         IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                         IBV_ACCESS_REMOTE_READ);

    if (ctx->mr == NULL)
        goto free_buf_out;

    ctx->cur_seed = rand();
    ctx->use_zeros = cfg->use_zeros;
    ctx->wrote_bytes = ctx->read_bytes = ctx->latency = ctx->count = 0;
    ctx->readback_addr = NULL;
    ctx->rloc = malloc(sizeof(*ctx->rloc));
    ctx->rloc->cur = ctx->rloc->start = (void *) rstart;
    ctx->rloc->end = (void *) rend;
    ctx->rloc->rkey = rkey;

    ctx->id = id;

    ctx->latency_max = 0;
    ctx->latency_min = ULLONG_MAX;

    return ctx;


free_buf_out:
    free(ctx->buf);

free_ctx_out:
    free(ctx);
    return NULL;
}

static void free_context(struct context *ctx)
{
    if (ctx == NULL) return;

    free(ctx->rloc);
    free(ctx->buf);
    free(ctx);
}

static void set_random_data(struct context *ctx)
{
    if (ctx->verbose) printf("Generate data block %d\n", ctx->cur_seed);
    srand(ctx->cur_seed);
    for (int i = 0; i < ctx->elem; i++)
        ctx->buf[i] = ctx->use_zeros ? 0 : rand();

    if (ctx->rloc->cur == ctx->rloc->start)
        ctx->first_seed = ctx->cur_seed;
}

static void check_random_data(struct context *ctx)
{
    int i;
    if (ctx->verbose) printf("Check data block %d\n", ctx->cur_seed);
    srand(ctx->cur_seed);
    for (i = 0; i < ctx->readback_len / sizeof(*ctx->buf); i++) {
        uint32_t expected = ctx->use_zeros ? 0 : rand();
        if (ctx->buf[i] != expected) {
            printf("%d %x %x\n", i, ctx->buf[i], expected);
            break;
        }
    }

    if (i != ctx->readback_len / sizeof(*ctx->buf))
        printf("Mismatch in read data!\n");

    ctx->cur_seed = rand();
}

static unsigned long long elapsed_utime(struct timeval start_time,
                                  struct timeval end_time)
{
    unsigned long long ret = (end_time.tv_sec - start_time.tv_sec)*1000000 +
        (end_time.tv_usec - start_time.tv_usec);
    return ret;
}

static size_t txn_length(struct context *ctx)
{
    size_t rlen = (ctx->rloc->end - ctx->rloc->cur) * sizeof(*ctx->rloc->end);
    if (rlen < ctx->buf_len) return rlen;
    return ctx->buf_len;
}

static void increment_rloc(struct context *ctx, size_t length)
{
    ctx->rloc->cur += length / sizeof(*ctx->rloc->cur);
    if (ctx->rloc->cur >= ctx->rloc->end)
        ctx->rloc->cur = ctx->rloc->start;
}

static int write_context(struct context *ctx)
{

    size_t length = txn_length(ctx);
    uint32_t *raddr = ctx->rloc->cur;

    if (ctx->verbose) printf("Writing %zd bytes to %p\n", length, raddr);

    gettimeofday(&ctx->start_time, NULL);
    int ret = rdma_post_write(ctx->id, ctx, ctx->buf, length, ctx->mr, 0,
                              (uint64_t) raddr, ctx->rloc->rkey);
    if (ret) return ret;

    ctx->readback_addr = raddr;
    ctx->readback_len = length;
    increment_rloc(ctx, length);

    return ret;
}

static int read_context(struct context *ctx, int read_only)
{
    if (ctx->verbose)
        printf("Reading %zd bytes from %p\n", ctx->readback_len,
               ctx->readback_addr);

    if (read_only) {
        ctx->readback_addr = ctx->rloc->cur;
        ctx->readback_len = txn_length(ctx);
    }

    gettimeofday(&ctx->start_time, NULL);
    int ret = rdma_post_read(ctx->id, ctx, ctx->buf, ctx->readback_len,
                             ctx->mr, 0, (uint64_t)ctx->readback_addr,
                             ctx->rloc->rkey);

    if (read_only)
        increment_rloc(ctx, ctx->readback_len);


    return ret;
}

static int start_transfer(const int nctxs, struct context *ctxs[nctxs],
                          struct config *cfg)
{
    int ret;

    for (int i = 0; i < nctxs; i++) {

        if (!cfg->read_only) {
            set_random_data(ctxs[i]);
            if ((ret = write_context(ctxs[i]))) {
                perror("Write Failed");
                return ret;
            }
        } else {
            if ((ret = read_context(ctxs[i], 1))) {
                perror("Read Failed");
                return ret;
            }
        }
    }

    return 0;
}

static int manage_transfer(struct rdma_cm_id *id, struct config *cfg)
{
    int ret = 0;

    while (1) {
        struct ibv_wc wc;
        ret = rdma_get_send_comp(id, &wc);
        if (ret < 0) {
            perror("Waiting for completions");
            return ret;
        }

        if (ret == 0) continue;

        if (wc.status != IBV_WC_SUCCESS) {
            fprintf(stderr, "Completion returned failure: %s (%d)\n",
                    ibv_wc_status_str(wc.status), wc.status);
            return -1;
        }

        struct context *ctx = (struct context *) wc.wr_id;

        if (cfg->latency){
            struct timeval end_time;
            gettimeofday(&end_time, NULL);
            unsigned long long latency = elapsed_utime(ctx->start_time, end_time);
            ctx->latency += latency;
            ctx->count++;
            if ( latency < ctx->latency_min )
                ctx->latency_min = latency;
            if ( latency > ctx->latency_max )
                ctx->latency_max = latency;
        }

        size_t byte_len = cfg->block_size;

        switch (wc.opcode) {
        case IBV_WC_RDMA_WRITE:
            ctx->wrote_bytes += byte_len;

            if (!cfg->write_only) {
                memset(ctx->buf, 0xaa, ctx->buf_len);
                if ((ret = read_context(ctx, 0))) {
                    perror("Read Failed");
                    return -1;
                }
            } else {
                if (ctx->wrote_bytes > cfg->count)
                    return 0;

                set_random_data(ctx);
                if ((ret = write_context(ctx))) {
                    perror("Write Failed");
                    return -1;
                }
            }

            break;
        case IBV_WC_RDMA_READ:
            ctx->read_bytes+= byte_len;

            if (!cfg->read_only)
                check_random_data(ctx);

            if (ctx->read_bytes > cfg->count)
                return 0;

            if (!cfg->read_only) {
                set_random_data(ctx);
                if ((ret = write_context(ctx))) {
                    perror("Write Failed");
                    return -1;
                }
            } else {
                if ((ret = read_context(ctx, 1))) {
                    perror("Read Failed");
                    return -1;
                }
            }

            break;
        default:
            printf("Unknown op code: %d\n", wc.opcode);
        }
    }
}

static void report_result(const int nctxs, struct context *ctxs[nctxs],
                          struct timeval *start_time, struct timeval *end_time)
{
    long long wrote_bytes = 0, read_bytes = 0, latency = 0,
        latency_min = ULLONG_MAX, latency_max = 0, count = 0;
    size_t total_bytes = 0;

    for (int i = 0; i < nctxs; i++) {
        wrote_bytes += ctxs[i]->wrote_bytes;
        read_bytes += ctxs[i]->read_bytes;
        total_bytes += ctxs[i]->wrote_bytes + ctxs[i]->read_bytes;
        count += ctxs[i]->count;
        latency += ctxs[i]->latency;
        if ( ctxs[i]->latency_min < latency_min )
            latency_min = ctxs[i]->latency_min;
        if ( ctxs[i]->latency_max > latency_max )
            latency_max = ctxs[i]->latency_max;
    }

    const char *w_suffix = suffix_binary_get(&wrote_bytes);
    const char *r_suffix = suffix_binary_get(&read_bytes);

    fprintf(stderr, "\n");
    if (wrote_bytes)
        fprintf(stderr, "Wrote:   %6lld%sB\n", wrote_bytes, w_suffix);
    if (read_bytes)
        fprintf(stderr, "Read:    %6lld%sB\n", read_bytes, r_suffix);
    fprintf(stderr, "Transfered: ");
    report_transfer_rate(stderr, start_time, end_time, total_bytes);
    fprintf(stderr, "\n");
    if (latency)
        fprintf(stderr, "Latency (mean/min/max):    ( %lld / %lld / %lld ) us\n", latency/count,
                latency_min, latency_max);
}

static void wait_for_goahead(struct rdma_cm_id *id, uint32_t *buf,
                             struct ibv_mr *mr)
{
    struct ibv_wc wc;

    if (rdma_post_recv(id, NULL, buf, 0, mr)) {
        perror("rdma_post_recv");
        return;
    }

    if (rdma_get_recv_comp(id, &wc) <= 0){
        perror("rdma_get_recv_comp");
        return;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Recv Completion reported failure: %s (%d)\n",
                ibv_wc_status_str(wc.status), wc.status);
        return;
    }

    printf("GoAhead Received Succesfully.\n");
}

int main(int argc, char *argv[])
{
    int ret = 0;
    struct config cfg;
    const struct common_priv_data *priv_data;
    struct timeval start_time, end_time;

    argconfig_parse(argc, argv, program_desc, command_line_options,
                    &defaults, &cfg, sizeof(cfg));

    if (cfg.show_version) {
        printf("Donard RDMA client version %s\n", VERSION);
        return 0;
    }

    if (cfg.read_only && cfg.write_only) {
        fprintf(stderr, "ERROR: -r and -w options are mutually exclusive!\n");
        return -1;
    }

    unsigned int seed = time(NULL);
    printf("Seed: %d\n", seed);
    srand(seed);

    const int nctxs = cfg.nctxs;
    struct context *ctxs[nctxs];

    struct rdma_cm_id *id = do_connect(&cfg);
    if (id == NULL) return -1;

    if (id->event->param.conn.private_data_len < sizeof(struct common_priv_data)) {
        fprintf(stderr, "ERROR: Unexpected private data length!\n");
        ret = -1;
        goto disconnect;
    }

    priv_data = id->event->param.conn.private_data;

    printf("Remote Buffer: 0x%" PRIx64 " : length %zdKiB : bs = %zdB\n",
           priv_data->buffer_addr, priv_data->buffer_length/1024, cfg.block_size);

    size_t chunk_size = (priv_data->buffer_length / nctxs) & ~3;
    uint64_t start = priv_data->buffer_addr;
    uint64_t end = start + priv_data->buffer_length;

    memset(ctxs, 0, sizeof(ctxs));

    for (int i = 0; i < nctxs; i++) {
        uint64_t cur_end = start + chunk_size;
        if (cur_end > end || cur_end <= start)
            cur_end = end;

        ctxs[i] = init_context(id, cfg.block_size, &cfg,
                               start, cur_end, priv_data->buffer_rkey);
        start = cur_end;

        if (ctxs[i] == NULL) {
            perror("Could not create context");
            ret = -1;
            goto free_contexts;
        }
    }

    if (!cfg.send_recv_dis)
    {
        printf("Testing Send/Recv\n");
        common_test_recv(id, ctxs[0]->buf, ctxs[0]->mr, COMMON_A1, COMMON_B1);
        common_test_send(id, ctxs[0]->buf, ctxs[0]->mr, COMMON_A2, COMMON_B2);
        wait_for_goahead(id, ctxs[0]->buf, ctxs[0]->mr);
        printf("\n");
    }

    gettimeofday(&start_time, NULL);
    if (cfg.read_only)
        printf("Testing Reads\n");
    else if (cfg.write_only)
        printf("Testing Writes\n");
    else
        printf("Testing Read/Write\n");

    start_transfer(nctxs, ctxs, &cfg);
    if (manage_transfer(id, &cfg) )
        goto free_contexts;

    gettimeofday(&end_time, NULL);

    struct common_seed_data seed_data = {
        .seed = ctxs[0]->first_seed,
        .length = cfg.read_only ? 0 : cfg.block_size,
        .use_zeros = cfg.use_zeros ? 1 : 0,
    };

    rdma_post_send(id, NULL, &seed_data, sizeof(seed_data), NULL,
                   IBV_SEND_INLINE);

    report_result(nctxs, ctxs, &start_time, &end_time);

free_contexts:

    for (int i = 0; i < nctxs; i++)
        free_context(ctxs[i]);

disconnect:
    rdma_disconnect(id);
    rdma_destroy_ep(id);

    return ret;
}

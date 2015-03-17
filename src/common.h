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
//     RDMA Common Structures
//
////////////////////////////////////////////////////////////////////////

#ifndef __DONARD_RDMA_COMMON_H__
#define __DONARD_RDMA_COMMON_H__

#include <stdint.h>
#include <stdlib.h>
#include <rdma/rdma_verbs.h>
#include <stdio.h>

struct common_priv_data {
    uint64_t buffer_addr;
    uint32_t buffer_rkey;
    size_t   buffer_length;
};

struct common_seed_data {
    unsigned int seed;
    size_t length;
    int use_zeros;
};

#define COMMON_A1 8453
#define COMMON_B1 54783
#define COMMON_A2 458739
#define COMMON_B2 7884

static unsigned long long elapsed_utime(struct timeval start_time,
                                  struct timeval end_time)
{
    unsigned long long ret = (end_time.tv_sec - start_time.tv_sec)*1000000 +
        (end_time.tv_usec - start_time.tv_usec);
    return ret;
}

static void common_test_send(struct rdma_cm_id *id, uint32_t *buf,
                             struct ibv_mr *mr, int a, int b)
{
    struct ibv_wc wc;

    for (int i = 0; i < 32; i++)
        buf[i] = a*i + b;

    if (rdma_post_send(id, NULL, buf, 32*sizeof(*buf), mr, 0)) {
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

    printf("Send Completed Successfully.\n");

}

static void common_test_recv(struct rdma_cm_id *id, uint32_t *buf,
                             struct ibv_mr *mr, int a, int b)
{
    struct ibv_wc wc;

    if (rdma_post_recv(id, NULL, buf, 32*sizeof(*buf), mr)) {
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

    for (int i = 0; i < 32; i++) {
        if (buf[i] != a*i+b) {
            printf("%d  %08x %08x\n", i, buf[i], a*i+b);
            printf("Incorrect data recieved!\n");
            return;
        }
    }

    printf("Recv Completed Succesfully.\n");
}


#endif

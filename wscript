

from waflib import Configure, Options
Configure.autoconfig = True

def options(opt):
    opt.load("compiler_c gnu_dirs")
    opt.load("version", tooldir="waftools")

def configure(conf):
    conf.load("compiler_c gnu_dirs")
    conf.load("version", tooldir="waftools")

    conf.env.INCLUDES = ["."]
    conf.env.CXXFLAGS = ["-O2", "-Wall", "-Werror", "-g"]
    conf.env.CFLAGS = conf.env.CXXFLAGS + ["-std=gnu99", "-D_GNU_SOURCE"]

    conf.check_cc(fragment="int main() { return 0; }\n")


    conf.check(header_name="rdma/rdma_cma.h", lib="rdmacm",
               uselib_store="RDMACM")
    conf.check(header_name="infiniband/verbs.h", lib="ibverbs",
               uselib_store="IBVERBS")
    conf.check(header_name="argconfig/argconfig.h", lib="argconfig",
               uselib_store="ARGCONFIG")
    conf.check(header_name="donard/pinpool.h", lib="donard",
               uselib_store="DONARD", mandatory=False)


def build(bld):
    bld.load("version", tooldir="waftools")

    bld.program(source="src/server.c",
                target="donard_rdma_server",
                use="DONARD RDMACM IBVERBS ARGCONFIG")

    bld.program(source="src/client.c",
                target="donard_rdma_client",
                use="DONARD RDMACM IBVERBS ARGCONFIG")

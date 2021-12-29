CC = clang

MAPPEROBJ = tc_mapper.o
MAPPERSRC = tc_mapper.c

LIBBPFDIR = libbpf/src
LIBBPFOBJS = $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/libbpf.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_errno.o $(LIBBPFSRC)/staticobjs/netlink.o $(LIBBPFSRC)/staticobjs/nlattr.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/str_error.o $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/xsk.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf_dump.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/ringbuf.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/strset.o $(LIBBPFSRC)/staticobjs/gen_loader.o $(LIBBPFSRC)/staticobjs/relo_core.o

OUTOBJ = tc_out.o
OUTSRC = tc_out.c

IPIPMAPPERSRC = ipipmapper.c
COMMONOBJS = src/cmdline.o

LIBBPFSRC = libbpf/src

all: ipipmapper mapper out
libbpf:
	$(MAKE) -C $(LIBBPFDIR)
ipipmapper: $(COMMONOBJS)
	$(CC) -I$(LIBBPFSRC) $(COMMONOBJS) -lelf -lz src/$(IPIPMAPPERSRC) $(LIBBPFOBJS) -o ipipmapper
mapper:
	$(CC) -I$(LIBBPFSRC) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/$(MAPPERSRC) -o src/tc_mapper.bc
	llc -march=bpf -filetype=obj src/tc_mapper.bc -o $(MAPPEROBJ)
out:
	$(CC) -I$(LIBBPFSRC) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/$(OUTSRC) -o src/tc_out.bc
	llc -march=bpf -filetype=obj src/tc_out.bc -o $(OUTOBJ)
clean:
	rm -f *.o
	rm -f src/*.bc
	rm -f src/*.o
	rm -f ipipmapper
install:
	mkdir -p /etc/IPIPMapper
	cp -f ipipmapper /usr/bin/
	cp -f tc_mapper.o /etc/IPIPMapper/
	cp -f tc_out.o /etc/IPIPMapper/
	cp -n systemd/IPIPMapper.service /etc/systemd/system/IPIPMapper.service
.PHONY: ipipmapper mapper out
.DEFAULT: all
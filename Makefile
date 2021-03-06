CC = clang

MAPPEROBJ = tc_mapper.o
MAPPERSRC = tc_mapper.c

OUTOBJ = tc_out.o
OUTSRC = tc_out.c

IPIPMAPPERSRC = ipipmapper.c
COMMONOBJS = src/cmdline.o

LIBBPFSRC = libbpf/src

all: ipipmapper mapper out
ipipmapper: $(COMMONOBJS)
	$(CC) $(COMMONOBJS) src/$(IPIPMAPPERSRC) -o ipipmapper
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
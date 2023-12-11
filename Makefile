CC = clang

BUILD_DIR = build
SRC_DIR = src

ETC_DIR = /etc/IPIPMapper
INSTALL_DIR = /usr/bin

LIBBPF_DIR = libbpf
LIBBPF_SRC = $(LIBBPF_DIR)/src

LIBBPF_OBJS = $(LIBBPF_SRC)/staticobjs/bpf.o $(LIBBPF_SRC)/staticobjs/btf.o $(LIBBPF_SRC)/staticobjs/libbpf.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/libbpf_errno.o $(LIBBPF_SRC)/staticobjs/netlink.o $(LIBBPF_SRC)/staticobjs/nlattr.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/str_error.o $(LIBBPF_SRC)/staticobjs/libbpf_probes.o $(LIBBPF_SRC)/staticobjs/xsk.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/btf_dump.o $(LIBBPF_SRC)/staticobjs/hashmap.o $(LIBBPF_SRC)/staticobjs/ringbuf.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/strset.o $(LIBBPF_SRC)/staticobjs/gen_loader.o $(LIBBPF_SRC)/staticobjs/relo_core.o

MAPPER_OBJ = $(BUILD_DIR)/tc_mapper.o
MAPPER_SRC = $(SRC_DIR)/tc_mapper.c

OUT_OBJ = $(BUILD_DIR)/tc_out.o
OUT_SRC = $(SRC_DIR)/tc_out.c

IPIPMAPPER_OUT = ipipmapper
IPIPMAPPER_SRC = $(SRC_DIR)/ipipmapper.c

CMDLINE_OBJ = $(BUILD_DIR)/cmd_line.o
CMDLINE_SRC = $(SRC_DIR)/cmdline.c

all: build_dir libbpf_objs cmdline ipip_mapper mapper out
build_dir:
	mkdir -p build
libbpf_objs:
	$(MAKE) -C $(LIBBPF_SRC)
cmdline:
	$(CC) -O2 -shared -fPIC $(CMDLINE_SRC) -o $(CMDLINE_OBJ)
ipip_mapper: $(CMDLINE_OBJ)
	$(CC) -I$(LIBBPF_SRC) $(CMDLINE_OBJ) -lelf -lz $(IPIPMAPPER_SRC) $(LIBBPF_OBJS) -o $(IPIPMAPPER_OUT)
mapper:
	$(CC) -I$(LIBBPF_SRC) -O2 -g -target bpf -c $(MAPPER_SRC) -o $(MAPPER_OBJ)
out:
	$(CC) -I$(LIBBPF_SRC) -O2 -g -target bpf -c $(OUT_SRC) -o $(OUT_OBJ)
clean:
	rm -f $(BUILD_DIR)/*
	rm -f $(IPIPMAPPER_OUT)
install:
	mkdir -p $(ETC_DIR)
	cp -f ipipmapper $(INSTALL_DIR)
	cp -f $(MAPPER_OBJ) $(ETC_DIR)
	cp -f $(OUT_OBJ) $(ETC_DIR)
	cp -n systemd/IPIPMapper.service /etc/systemd/system/IPIPMapper.service
.PHONY: ipip_mapper mapper out
.DEFAULT: all
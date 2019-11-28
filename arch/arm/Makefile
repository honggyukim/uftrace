sdir := $(srcdir)/arch/arm
odir := $(objdir)/arch/arm

LINKFLAGS := -r

include $(srcdir)/Makefile.include

ARCH_ENTRY_SRC = $(wildcard $(sdir)/*.S)
ARCH_MCOUNT_SRC = $(wildcard $(sdir)/mcount-*.c)
ARCH_UFTRACE_SRC = $(sdir)/cpuinfo.c

ARCH_MCOUNT_OBJS  = $(patsubst $(sdir)/%.S,$(odir)/%.op,$(ARCH_ENTRY_SRC))
ARCH_MCOUNT_OBJS += $(patsubst $(sdir)/%.c,$(odir)/%.op,$(ARCH_MCOUNT_SRC))
ARCH_UFTRACE_OBJS = $(patsubst $(sdir)/%.c,$(odir)/%.o,$(ARCH_UFTRACE_SRC))

FLAGS=-iquote /home/honggyu/uftrace -iquote /home/honggyu/uftrace -iquote /home/honggyu/uftrace/arch/arm -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers -O2 -g -DHAVE_CXA_DEMANGLE -DHAVE_LIBPYTHON2 -DHAVE_LIBLUAJIT -I/usr/include/luajit-2.1 -DHAVE_PERF_CLOCKID -DHAVE_PERF_CTXSW -DHAVE_ARM_HARDFP -DHAVE_LIBNCURSES -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 -DHAVE_LIBELF -DHAVE_LIBDW  -DHAVE_LIBCAPSTONE -I/usr/include/capstone   -fPIC -fvisibility=hidden -fno-omit-frame-pointer

all: $(odir)/entry.op

$(odir)/mcount-entry.op: $(ARCH_MCOUNT_OBJS)
	$(QUIET_LINK)$(LD) $(LINKFLAGS) -o $@ $^

$(odir)/uftrace.o: $(ARCH_UFTRACE_OBJS)
	$(QUIET_LINK)$(LD) $(LINKFLAGS) -o $@ $^

$(odir)/%.op: $(sdir)/%.S
	$(QUIET_ASM)$(CC) $(FLAGS) -c -o $@ $<
#	$(QUIET_ASM)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(odir)/%.op: $(sdir)/%.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(odir)/%.o: $(sdir)/%.c
	$(QUIET_CC)$(CC) $(UFTRACE_CFLAGS) -c -o $@ $<

clean:
	$(RM) $(odir)/*.op $(odir)/*.o

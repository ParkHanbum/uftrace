#-*- mode: makefile -*-
ifndef UFTRACE_HOME
  uftrace_home = $(CURDIR)/..
else
  uftrace_home = $(UFTRACE_HOME)
endif

include $(uftrace_home)/Makefile.include
srcdir = $(CURDIR)

# set objdir to $(O) by default (if any)
ifeq ($(objdir),)
  ifneq ($(O),)
    objdir = $(O)
  else
    objdir = $(CURDIR)
  endif
endif

uname_M := $(shell uname -m 2>/dev/null || echo not)
ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

TARGET = plugin_skel.so plugin_nodejs.so

CFLAGS := -D_GNU_SOURCE -iquote $(uftrace_home) -iquote $(uftrace_home)/arch/$(ARCH) -fPIC
LDFLAGS := -shared -lrt -ldl -pthread -Wl,-z,noexecstack

ifeq ($(DEBUG), 1)
  CFLAGS += -O0 -g
else
  CFLAGS += -O2 -g
endif

PLUGIN_SRCS := $(srcdir)/plugin_skeleton.c $(srcdir)/plugin_nodejs.c
PLUGIN_UTILS_SRCS += $(srcdir)/utils/debug.c $(srcdir)/utils/regs.c
PLUGIN_UTILS_SRCS += $(srcdir)/utils/rbtree.c $(srcdir)/utils/filter.c
PLUGIN_UTILS_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/utils.c
PLUGIN_UTILS_SRCS += $(srcdir)/utils/script.c $(srcdir)/utils/script-python.c
PLUGIN_UTILS_SRCS += $(srcdir)/utils/auto-args.c $(srcdir)/utils/dwarf.c
PLUGIN_UTILS_SRCS += $(wildcard $(srcdir)/utils/symbol*.c)
PLUGIN_UTILS_OBJS := $(patsubst $(srcdir)/utils/%.c,$(objdir)/%.op,$(PLUGIN_UTILS_SRCS))

all: $(TARGET)

$(PLUGIN_UTILS_OBJS): $(objdir)/%.op: $(uftrace_home)/utils/%.c
	$(QUIET_CC_FPIC)$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(PLUGIN_SRCS)  $(PLUGIN_UTILS_OBJS)
	$(QUIET_CC_FPIC)$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	$(Q)$(RM) $(objdir)/*.o $(objdir)/*.op $(objdir)/plugin_skel.so

.PHONY: all

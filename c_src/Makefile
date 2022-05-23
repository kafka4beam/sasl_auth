# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT ?= $(notdir $(BASEDIR))
PROJECT := $(strip $(PROJECT))

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)]).")
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)]).")
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)]).")

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT).so

ifdef NORMAL_DEBUG
	EXTRA_C_FLAGS := -fPIC -g -O0
	MEMSAN_FLAGS := 
else ifdef MEMSAN_DEBUG
	MEMSAN_FLAGS := -fno-omit-frame-pointer -fsanitize=address
	OTP_PLATFORM := $(shell $(ERL_TOP)/erts/autoconf/config.guess)
	EXTRA_C_FLAGS := -fPIC -g -O0 $(MEMSAN_FLAGS) -I $(ERL_TOP)/erts/emulator/beam/ -I "$(ERL_TOP)/erts/include/$(OTP_PLATFORM)/"
else
	EXTRA_C_FLAGS := -g -fPIC -O3
	MEMSAN_FLAGS := 
endif

# System type and C compiler/flags.

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	KRB5_PREFIX ?= $(shell brew --prefix  krb5)
	CYRUS_PREFIX ?= $(shell brew --prefix cyrus-sasl)
	KRB5_INCLUDE ?= $(KRB5_PREFIX)/include
	CYRUS_INCLUDE ?= $(CYRUS_PREFIX)/include
	KRB5_LIB ?= $(KRB5_PREFIX)/lib
	CYRUS_LIB ?= $(CYRUS_PREFIX)/lib

	CC ?= cc
	CFLAGS ?= $(EXTRA_C_FLAGS) -std=c99 -finline-functions -Wall -Wextra -Wconversion -Wcast-align -Wformat=2 -Wformat-security \
			  -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wstrict-overflow \
			  -I$(CYRUS_INCLUDE) -I$(KRB5_INCLUDE)
	CXXFLAGS ?= -O3 -finline-functions -Wall -Wextra -Wconversion -Wcast-align -Wformat=2 -Wformat-security \
				-Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wstrict-overflow \
				-I$(CYRUS_INCLUDE) -I$(KRB5_INCLUDE)
	LDFLAGS ?= -flat_namespace -undefined suppress

	LDLIBS += -L$(CYRUS_LIB) -L$(KRB5_LIB)
else ifeq ($(UNAME_SYS), FreeBSD)
	CC ?= cc
	CFLAGS ?= $(EXTRA_C_FLAGS) -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
else ifeq ($(UNAME_SYS), Linux)
	CC ?= gcc
	CFLAGS ?= $(EXTRA_C_FLAGS) -std=c99 -finline-functions -Wall -Wextra -Wconversion -Wcast-align -Wformat=2 -Wformat-security \
			  -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wstrict-overflow
	CXXFLAGS ?= -O3 -finline-functions -Wall -Wextra -Wconversion -Wcast-align -Wformat=2 -Wformat-security \
				-Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wstrict-overflow
endif

CFLAGS += -fPIC -I$(ERTS_INCLUDE_DIR) -I$(ERL_INTERFACE_INCLUDE_DIR)
CXXFLAGS += -fPIC -I$(ERTS_INCLUDE_DIR) -I$(ERL_INTERFACE_INCLUDE_DIR)

LDLIBS += -L $(CURDIR) -L $(ERL_INTERFACE_LIB_DIR)  -lei -lkrb5 -lsasl2
LDFLAGS += -shared

# Verbosity.

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" -o -name "*.C" -o -name "*.cc" -o -name "*.cpp" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

$(C_SRC_OUTPUT): $(OBJECTS)
	@mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(C_SRC_OUTPUT)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS) $(CURDIR)/libei.a

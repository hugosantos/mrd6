ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
-include Makefile.options
endif
endif

CXX ?= g++

PLATFORM ?= OS_OTHER
SUPPORT_MODULES ?= yes
TARGET ?= mrd
PREFIX ?= /usr/local
STATIC_STDCXX ?= no
FULL_STATIC ?= no
NO_INLINE ?= no
OBJ_DIR ?= build

DEPS_DIR = $(OBJ_DIR)/.deps
MRD_VERSION_CPP = $(OBJ_DIR)/mrd.version.cpp
MODULES_CPP = $(OBJ_DIR)/modules.cpp

STATIC_MODULES ?= MLD PIM CONSOLE

KERNEL = $(shell uname -s)
ifeq ($(KERNEL),Linux)
	PLATFORM = OS_LINUX
endif
ifneq (,$(findstring BSD,$(KERNEL)))
	PLATFORM = OS_BSD
endif

ifeq ($(FULL_STATIC),yes)
	SUPPORT_MODULES = no
	LDCMD = -static
endif

ifeq ($(SUPPORT_MODULES),yes)
	MODULES ?= BGP
	LDCMD = -rdynamic
	LDMODCMD = -Wl,--as-needed
else
	MODULE_OPTIONS += MRD_NO_DYNAMIC_MODULE_LOADING
endif

INCLUDES = -I../include

NOW = $(shell date -u)

SOURCES = address.cpp address_set.cpp group.cpp icmp_inet6.cpp icmp.cpp \
	  interface.cpp ks_mfa.cpp log.cpp mfa.cpp mrd.cpp mrib.cpp node.cpp \
	  parser.cpp rib.cpp router.cpp timers.cpp support/objpool.cpp \
	  support/ptree.cpp

LDFLAGS += -ldl # mrd.cpp requires dl* functions

ifeq ($(PLATFORM),OS_LINUX)
	SOURCES += linux/us_mfa.cpp linux/linux_icmp_raw.cpp \
		   linux/linux_unicast_route.cpp linux/mrd_components.cpp \
		   linux/translator.cpp
endif

ifeq ($(PLATFORM),OS_BSD)
	SOURCES += bsd/bsd_rib.cpp bsd/mrd_components.cpp
endif

MLD_SOURCES = mld/mld_def.cpp mld/mld_router.cpp mld/mld_conf.cpp mld/mld_module.cpp
PIM_SOURCES = pim/pim_def.cpp pim/pim_router.cpp pim/pim_interface.cpp \
	      pim/pim_group.cpp pim/pim_source.cpp pim/pim_oif.cpp \
	      pim/pim_neighbour.cpp pim/pim_conf.cpp pim/pim_bsr.cpp \
	      pim/pim_module.cpp
CONSOLE_SOURCES = console/console.cpp console/telnet_console.cpp \
		  console/unix_console.cpp
BGP_SOURCES = bgp/bgp.cpp bgp/bgp_def.cpp
MSNIP_SOURCES = msnip/msnip_module.cpp
MRDISC_SOURCES = mrdisc/mrdisc_module.cpp
RIPNG_SOURCES = ripng/ripng.cpp
ZEBRA_SOURCES = zebra/zebra.cpp
MLD_EXT_SOURCES = mld/mld_def.cpp mld/mld_router.cpp mld/mld_conf.cpp \
		  extra/mld_ext.cpp

TEST_SOURCES = $(SOURCES) no-modules.cpp $(MRD_VERSION_CPP)
MRD_SOURCES = $(SOURCES) main.cpp $(MODULES_CPP) $(MRD_VERSION_CPP)

# used to build object list
ALL_SOURCES = $(SOURCES) main.cpp $(MRD_SOURCES) $(MLD_SOURCES) \
	      $(PIM_SOURCES) $(CONSOLE_SOURCES) $(BGP_SOURCES) \
	      $(MSNIP_SOURCES) $(MRDISC_SOURCES) $(RIPNG_SOURCES) \
	      $(ZEBRA_SOURCES)

# used in dependency generation
BUILT_SOURCES = $(SOURCES) main.cpp

MLD_TARGET	= mld.so
PIM_TARGET	= pim.so
CONSOLE_TARGET	= console.so
BGP_TARGET	= bgp.so
MSNIP_TARGET	= msnip.so
MRDISC_TARGET	= mrdisc.so
RIPNG_TARGET	= ripng.so
ZEBRA_TARGET	= zebra.so
MLD_EXT_TARGET	= mld_ext.so

EXTERNAL_MODULES = $(foreach module,$(MODULES),$($(module)_TARGET))

TESTS = tests/address_unittest tests/ptree_unittest tests/mrib_unittest

DEST_PREFIX = $(DESTDIR)$(PREFIX)

CXXFLAGS = $(INCLUDES) -ansi -Wall -Wno-multichar -fno-exceptions -fPIC \
	   -fno-strict-aliasing -D$(PLATFORM) $(addprefix -D,$(MODULE_OPTIONS))

ifeq ($(OPTIMIZE),yes)
	ifeq ($(SPACE_OPTIMIZE),yes)
		CXXFLAGS += -O3 -Os
	else
		CXXFLAGS += -O3
	endif
else
	CXXFLAGS += -g
	ifeq ($(NO_INLINE),yes)
		CXXFLAGS += -O0 -fno-inline
	else
		CXXFLAGS += -O2
	endif
endif

LDFLAGS += -lm
LDCMD += -Wl,--as-needed

ifeq ($(STATIC_STDCXX),no)
	LDFLAGS += -lstdc++
else
	LDFLAGS += `$(CXX) -print-file-name=libstdc++.a`
endif

TEST_OBJECTS = $(addprefix $(OBJ_DIR)/,$(TEST_SOURCES:.cpp=.o))
MRD_OBJECTS = $(addprefix $(OBJ_DIR)/,$(MRD_SOURCES:.cpp=.o))

all: $(TARGET) $(EXTERNAL_MODULES)

define module_template
BUILT_SOURCES += $$($(1)_SOURCES)
$$($(1)_TARGET): $$(addprefix $(OBJ_DIR)/,$($(1)_SOURCES:.cpp=.o))
	@echo "Module $$($(1)_TARGET)"
	@$(CXX) -shared $(LDMODCMD) $(CXXFLAGS) -o $$($(1)_TARGET) \
		$$(addprefix $(OBJ_DIR)/,$($(1)_SOURCES:.cpp=.o))
endef

define static_module_template
BUILT_SOURCES += $$($(1)_SOURCES)
MRD_OBJECTS += $$(addprefix $(OBJ_DIR)/,$($(1)_SOURCES:.cpp=.o))
endef

define unittest_template
BUILT_SOURCES += $(1).cpp
$(1): $(TEST_OBJECTS) $(1).cpp
	@echo "Linking $(1)"
	@$(CXX) $(LDCMD) $(CXXFLAGS) -o $(1) $(1).cpp $(TEST_OBJECTS) \
		$(LDFLAGS) -lboost_unit_test_framework
endef

# generate the required build rules for each module
$(foreach module,$(MODULES),$(eval $(call module_template,$(module))))
$(foreach module,$(STATIC_MODULES),$(eval $(call static_module_template,$(module))))
# generate the required build rules for each unit test
$(foreach test,$(TESTS),$(eval $(call unittest_template,$(test))))

$(TARGET): $(MRD_OBJECTS)
	@echo "Linking $(TARGET)"
	@$(CXX) $(LDCMD) $(CXXFLAGS) -o $@ $(MRD_OBJECTS) $(LDFLAGS)

install: $(TARGET) $(EXTERNAL_MODULES)
	install -D $(TARGET) $(DEST_PREFIX)/sbin/$(TARGET)
	install -D ../tools/mrd6sh $(DEST_PREFIX)/bin/mrd6sh
ifneq (,$(EXTERNAL_MODULES))
	mkdir -p $(DEST_PREFIX)/lib/mrd6/
	cp $(EXTERNAL_MODULES) $(DEST_PREFIX)/lib/mrd6/
endif

$(MRD_VERSION_CPP): $(SOURCES) Makefile Makefile.options
	@set -e; mkdir -p $(dir $@); \
		echo '/* This file is automatically generated */' > $(MRD_VERSION_CPP); \
		echo 'const char *BuildDate = "$(NOW)";' >> $(MRD_VERSION_CPP)

$(MODULES_CPP): Makefile Makefile.options
	@set -e; mkdir -p $(dir $@); \
		echo "Generating modules.cpp"; \
		scripts/generate-modules-cpp.pl $(STATIC_MODULES) > $(MODULES_CPP)

.PHONY: tests
tests: $(TESTS)

OPTIONS = Makefile.options

$(OPTIONS):
	@touch $@

$(DEPS_DIR)/%.d: %.cpp $(OPTIONS)
	@echo "Deps $<"
	@set -e; mkdir -p $(dir $@); \
		$(CXX) -MM -MT $@ -MT $(addprefix $(OBJ_DIR)/,$(<:.cpp=.o)) \
		       $(CXXFLAGS) $< > $@

DEPENDENCIES = $(addprefix $(DEPS_DIR)/,$(BUILT_SOURCES:.cpp=.d))

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
	-include $(DEPENDENCIES)
endif
endif

$(OBJ_DIR)/%.o: %.cpp $(OPTIONS)
	@echo "C++ $<"
	@set -e; mkdir -p $(dir $@); \
		$(CXX) -c $(CXXFLAGS) $< -o $@

clean:
	rm -rf $(TARGET) $(TESTS) $(EXTERNAL_MODULES) \
		$(addprefix $(OBJ_DIR)/,$(ALL_SOURCES:.cpp=.o))

distclean: clean
	rm -rf $(DEPS_DIR) $(MRD_VERSION_CPP) $(MODULES_CPP)

.PHONY: install clean distclean


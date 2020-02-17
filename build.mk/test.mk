# 
# This makefile builds the unit test executables
#
# To build, say, an executable in tests/test_x509
# from the project root directory, run the command:
# 
# 	make -f tests.mk -T=test_x509
# 
# this will compile the source files in tests/test_x509
# place the objects in tests/test_x509/obj
# and produce an executable 
#	tests/test_x509/text_x509

LIBTOOL = libtool
STATIC =-static
LIBOUT = libx509
LD         = clang++ -o
LDFLAGS    = -Wall -pedantic
PWD = $(shell pwd)
SRCDIR     = $(PWD)
INCDIR		= $(realpath $(PWD)/include)
OBJDIR     = $(PWD)/build.mk/obj
BINDIR     = $(PWD)/tests/$(T)
DEPSDIR = $(realpath $(PWD)/deps)
DEPSINC = $(realpath $(DEPSDIR)/include)
TARGET     = $(BINDIR)/$(T)
# DEBUG or RELEASE
BUILD_TYPE=

CXX        = clang++
CXX        = clang++
CXXFLAGS   = -std=c++14 \
	-I $(PWD)/tests \
	-I $(INCDIR) \
	-I $(INCDIR)/cert \
	-I $(INCDIR)/cert/helpers \
	-I $(INCDIR)/cert/oo \
	-I $(INCDIR)/cert/store \
	-I $(INCDIR)/cert/x509 \
	-I $(DEPSINC) \
	-Wall \
	-Wextra \
	-Wno-unused-function \
	-Wno-unused-label \
	-Wno-unused-parameter \
	-Wno-unused-variable \
	-Wunused-value \
	-Wno-empty-body \
	-Wno-unused-private-field \
	-Os

LIBX509=$(realpath libx509) 
LIBSSL=$(realpath deps/lib/libcrypto.a) $(realpath deps/lib/libssl.a) 
LIBBOOST=$(realpath deps/lib/libboost_filesystem.a)

LIBS=$(LIBX509) $(LIBSSL) $(LIBBOOST)

T=test_x5099
TEST_DIR=$(PWD)/tests/$(T)
TEST_SOURCES   := $(wildcard $(TEST_DIR)/*.cpp) 
T_SOURCES=$(TEST_SOURCES)
T_SRCDIR=$(TEST_DIR)
T_OBJDIR=$(OBJDIR)/$(T)
T_TARGET = $(PWD)/tests/$(T)/$(T)
T_BINDIR=$(TEST_DIR)

# all .hpp files in$(project_dir)/include + all *.hpp files in $(project_dir)/tests and then all *.hpp files in the specific test directory
INCLUDES  = $(shell find $(INCDIR) -type f -name "*.hpp") \
	$(shell find $(PWD)/tests -type f -name "*.hpp") \
	$(shell find $(TEST_DIR) -type f -name "*.hpp")

# store objects in an 'obj' subdir of a the specific test directory
T_OBJECTS   = $(T_SOURCES:$(T_SRCDIR)/%.cpp=$(T_OBJDIR)/%.o)

RM         = rm -f

.PHONY: t_all
t_all: $(T_TARGET)

.PHONY: dump
dump:
	@echo
	@echo =================================================================
	@echo tests Dir: $(TEST_DIR)
	@echo Target: $(TARGET)
	@echo T_Target: $(T_TARGET)
	@echo test.mk PWD: $(PWD)
	@echo T_SOURCE DIR: $(T_SRCDIR)
	@echo INCDIR  $(INCDIR)
	@echo DEPSINC $(DEPSINC)
	@echo T_OBJDIR $(T_OBJDIR)
	@echo T_OBJECTS: $(T_OBJECTS)
	@echo T_SOURCES: $(T_SOURCES)
	@echo Includes: $(INCLUDES)

$(T_TARGET): $(T_OBJECTS) $(LIBX509)
	@mkdir -p $(@D)
	@$(LD) $@ $(LDFLAGS) $(T_OBJECTS) $(LIBS)
	@echo "Linking complete!" $(T_TARGET)

$(T_OBJECTS): $(T_OBJDIR)/%.o : $(T_SRCDIR)/%.cpp $(INCLUDES)
	@mkdir -p $(@D)
	@$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully! INTO: "$@

.PHONY: t_clean
t_clean:
	$(RM) $(T_OBJECTS)
	@echo "Cleanup complete!"

.PHONY: t_remove
t_remove: clean
	$(RM) $(T_BINDIR)/$(T_TARGET)
	@echo "Executable removed!"

.PHONY: t_run
t_run: $(TARGET)
	$(T_TARGET)



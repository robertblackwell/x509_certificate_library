# 
# This makefile build the library libx509 and deposits the result in ${project_dir}/libx509.a
# 

LIBTOOL = libtool
STATIC =-static
LD         = clang++ -o
LDFLAGS    = -Wall -pedantic

PWD = $(shell pwd)
SRCDIR     = $(PWD)/src
INCDIR		= $(PWD)/include
OBJDIR     = $(PWD)/build.mk/obj
OBJECT_DIRS = $(OBJDIR)/cert_authority $(OBJDIR)/handshaker $(OBJDIR)/helpers $(OBJDIR)/oo $(OBJDIR)/store $(OBJDIR)/x509

LIBDIR     = $(PWD)/lib
LIBOUT = libx509
DEPSDIR = $(PWD)/deps
DEPSINC = $(DEPSDIR)/include
TARGET     = $(TARGET)

CXX        = clang++
CXXFLAGS   = -std=c++14 \
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

CXXFLAGS_MORE_WARNINGS = \
	-Wpointer-arith \
	-Wcast-qual \
	-Wno-cast-qual \
	-Wno-missing-braces \
	-Wempty-body \
	-Wno-error=uninitialized \
	-Wno-error=deprecated-declarations \
	-Wno-reserved-id-macro \
	-pedantic-errors -pedantic \
	-Wno-disabled-macro-expansion \
	-Wno-zero-as-null-pointer-constant \
	-Wno-old-style-cast \
	-Wno-deprecated-dynamic-exception-spec \
	-Wnon-modular-include-in-framework-module \
	-Werror=non-modular-include-in-framework-module \
	-Wno-trigraphs \
	-Wno-missing-field-initializers \
	-Wno-missing-prototypes \
	-Werror=return-type \
	-Wunreachable-code \
	-Werror=deprecated-objc-isa-usage \
	-Werror=objc-root-class \
	-Wno-non-virtual-dtor \
	-Wno-overloaded-virtual \
	-Wno-exit-time-destructors \
	-Wno-missing-braces \
	-Wparentheses \
	-Wswitch \
	-Wno-unused-function \
	-Wno-unused-label \
	-Wno-unused-parameter \
	-Wno-unused-variable \
	-Wunused-value \
	-Wno-empty-body \
	-Wuninitialized \
	-Wconditional-uninitialized \
	-Wno-unknown-pragmas \
	-Wno-shadow \
	-Wno-four-char-constants \
	-Wno-conversion \
	-Wconstant-conversion \
	-Wint-conversion \
	-Wbool-conversion \
	-Wenum-conversion \
	-Wno-float-conversion \
	-Wnon-literal-null-conversion \
	-Wobjc-literal-conversion \
	-Wno-shorten-64-to-32 \
	-Wno-newline-eof \
	-Wno-c++11-extensions \
	-Wdeprecated-declarations \
	-Winvalid-offsetof \
	-Wno-sign-conversion \
	-Winfinite-recursion \
	-Wmove \
	-Wno-comma \
	-Wblock-capture-autoreleasing \
	-Wstrict-prototypes \
	-Wrange-loop-analysis \
	-Wno-semicolon-before-method-body \
	-Wunguarded-availability \
	-Wno-vla-extension \
	-Wno-unused-private-field \
             -Os


SOURCES   := $(wildcard $(SRCDIR)/*.cpp) \
	$(wildcard $(SRCDIR)/cert_authority/*.cpp) \
	$(wildcard $(SRCDIR)/handshaker/*.cpp) \
	$(wildcard $(SRCDIR)/helpers/*.cpp) \
	$(wildcard $(SRCDIR)/cert_helpers/*.cpp) \
	$(wildcard $(SRCDIR)/oo/*.cpp) \
	$(wildcard $(SRCDIR)/store/*.cpp) \
	$(wildcard $(SRCDIR)/x509/*.cpp)


INCLUDES  := $(shell find $(INCDIR) -type f -name "*.hpp")
OBJECTS   := $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)



RM         = rm -f

.PHONY: all
all: $(OBJECTS) $(LIBOUT)

dump:
	@echo
	@echo ============================================================
	@echo lib.mk PWD=$(PWD)
	@echo Source Dir: $(SRCDIR)
	@echo INCDIR  $(INCDIR)
	@echo Source $(SOURCES)
	@ObjectDir: $(OBJDIR)
	@echo OBjects: $(OBJECTS)

$(OBJECT_DIRS):
	mkdir -p $(OBJDIR)/cert_authority
	mkdir -p $(OBJDIR)/handshaker
	mkdir -p $(OBJDIR)/helpers
	mkdir -p $(OBJDIR)/oo
	mkdir -p $(OBJDIR)/store
	mkdir -p $(OBJDIR)/x509

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.cpp
	@mkdir -p $(@D)
	@$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"


$(LIBOUT): $(OBJECT_DIRS) $(OBJECTS)
	@mkdir -p $(@D)
	$(LIBTOOL) $(STATIC) -o $@ $(OBJECTS)


.PHONY: clean
clean:
	@$(RM) $(OBJECTS)
	@echo "Cleanup complete!"


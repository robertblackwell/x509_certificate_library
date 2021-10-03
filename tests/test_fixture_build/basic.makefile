

LIBTOOL = libtool
STATIC =-static
LIBOUT = libx509
LD         = clang++ -o
LDFLAGS    = -Wall -pedantic
PWD = $(shell pwd)
SRCDIR     = $(PWD)
INCDIR		= $(realpath $(PWD)/../../include)
OBJDIR     = $(PWD)/obj
BINDIR     = $(PWD)/bin
DEPSDIR = $(realpath $(PWD)/../../deps)
DEPSINC = $(realpath $(DEPSDIR)/include)
TARGET     = test_x509

CXX        = clang++
CXXFLAGS   = -std=c++14 \
	-I $(INCDIR) \
	-I $(INCDIR)/cert \
	-I $(INCDIR)/cert/helpers \
	-I $(INCDIR)/cert/oo \
	-I $(INCDIR)/cert/store \
	-I $(INCDIR)/cert/x509 \
	-I $(DEPSINC) \
	 -Wall -Wextra -Werror -Wpointer-arith -Wcast-qual \
	-Wno-cast-qual \
	 -Wno-missing-braces -Wempty-body -Wno-error=uninitialized \
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


SOURCES   := $(wildcard $(SRCDIR)/*.cpp) 


INCLUDES  := $(shell find $(INCDIR) -type f -name "*.hpp")
OBJECTS   := $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

RM         = rm -f

all: $(TARGET) $(OBJDIR) $(OBJECTS)

.PHONY: dump
dump:
	echo PWD: $(PWD)
	echo Source Dir: $(SRCDIR)
	echo INCDIR  $(INCDIR)
	echo DEPSINC $(DEPSINC)
	echo OBJDIR $(OBJDIR)
	echo OBJECTS: $(OBJECTS)

$(TARGET): $(OBJECTS)
	@$(LD) $@ $(LDFLAGS) $(OBJECTS) \
		$(realpath ../../libx509) \
		$(realpath ../../deps/lib/libcrypto.a) $(realpath ../../deps/lib/libssl.a) \
		$(realpath ../../deps/lib/libboost_filesystem.a)
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.cpp 
	@$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully! INTO: "$@

$(OBJDIR):
	mkdir -p $(OBJDIR)

.PHONY: clean
clean:
	@$(RM) $(OBJECTS)
	@echo "Cleanup complete!"

.PHONY: remove
remove: clean
	@$(RM) $(BINDIR)/$(TARGET)
	@echo "Executable removed!"


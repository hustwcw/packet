################OPTION###################
CCOMPILE = gcc
CPPCOMPILE = g++
COMPILEOPTION = -c -g -Wall
INCLUDEDIR = -I/usr/local/ssl/include -I/usr/local/include
LINK = gcc
LINKOPTION = -g -o parsepkg_test
LIBDIRS = -L/usr/local/ssl/lib -lssl -lcrypto -ldl -L/usr/local/lib -lz
OBJS = unit_test.o packet.o util.o compress/cps_zlib.o iks/utility.o iks/stream.o iks/sax.o iks/ikstack.o iks/iks.o iks/dom.o encrypt/ert_rsa.o encrypt/ert_des3.o encrypt/ert_aes.o
OUTPUT = parsepkg_test
SHAREDLIB = 
APPENDLIB = 
$(OUTPUT): $(OBJS) $(APPENDLIB)
	$(LINK) $(OBJS)  $(LINKOPTION) $(LIBDIRS) $(SHAREDLIB) $(APPENDLIB)

clean: 
	rm -f $(OBJS)
	rm -f $(OUTPUT)
all: clean $(OUTPUT)
.PRECIOUS:%.cpp %.c %.C
.SUFFIXES:
.SUFFIXES:  .c .o .cpp .ecpp .pc .ec .C .cc .cxx

.cpp.o:
	$(CPPCOMPILE) -c -o $*.o $(COMPILEOPTION) $(INCLUDEDIR)  $*.cpp
	
.cc.o:
	$(CCOMPILE) -c -o $*.o $(COMPILEOPTION) $(INCLUDEDIR)  $*.cx

.cxx.o:
	$(CPPCOMPILE) -c -o $*.o $(COMPILEOPTION) $(INCLUDEDIR)  $*.cxx

.c.o:
	$(CCOMPILE) -c -o $*.o $(COMPILEOPTION) $(INCLUDEDIR) $*.c

.C.o:
	$(CPPCOMPILE) -c -o $*.o $(COMPILEOPTION) $(INCLUDEDIR) $*.C	

.ecpp.C:
	$(ESQL) -e $(ESQL_OPTION) $(INCLUDEDIR) $*.ecpp 
	
.ec.c:
	$(ESQL) -e $(ESQL_OPTION) $(INCLUDEDIR) $*.ec
	
.pc.cpp:
	$(PROC)  CPP_SUFFIX=cpp $(PROC_OPTION)  $*.pc

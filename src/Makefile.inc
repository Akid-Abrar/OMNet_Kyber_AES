# Include paths for headers
CFLAGS += -I/home/veins/liboqs/install/include -I/usr/include/openssl
CXXFLAGS += -I/home/veins/liboqs/install/include -I/usr/include/openssl

# Library paths
LDFLAGS += -L/home/veins/liboqs/install/lib

# Libraries to link against
LIBS += -loqs -lssl -lcrypto -lpthread

CXX=g++
CXXFLAGS=-Wall -Wextra -g
LDLIBS=-lpcap

TARGET=send-arp
SRCS=main.cpp ip.cpp mac.cpp
OBJS=$(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDLIBS) -o $(TARGET)

main.o: main.cpp ethhdr.h arphdr.h mac.h ip.h
ip.o: ip.cpp ip.h
mac.o: mac.cpp mac.h

clean:
	rm -f $(TARGET) $(OBJS)

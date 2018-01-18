CC=g++
LIBS=-l
SDIR=src
ODIR=obj
AT=@
INC=-Iinclude

SRCS:=$(wildcard $(SDIR)/*.cpp)
OBJS=$(patsubst $(SDIR)/%.cpp, $(ODIR)/%.o, $(SRCS))
	
$(ODIR)/%.o: $(SDIR)/%.cpp
	$(AT)mkdir -p $(ODIR)
	$(AT)$(CC) $(INC) -c $< -o $@ $(LIBS)pcap

all: $(OBJS)
	$(AT)$(CC) $(INC) -o mydump $^ $(LIBS)pcap
	@echo "Created mydump"

clean:
	$(AT)rm -f $(ODIR)/*.o
	$(AT)rm -rf $(ODIR)
	$(AT)rm -rf mydump
run:
	sudo ./my_dump

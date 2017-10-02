CC=g++
LIBS=-l
SDIR=src
ODIR=OBJ
AT=@
INC=-Iinclude

SRCS:=$(wildcard $(SDIR)/*.cpp)
OBJS=$(patsubst $(SDIR)/%.cpp, $(ODIR)/%.o, $(SRCS))
	
$(ODIR)/%.o: $(SDIR)/%.cpp
	$(AT)mkdir -p $(ODIR)
	$(AT)$(CC) $(INC) -c $< -o $@ $(LIBS)pcap

all: $(OBJS)
	$(AT)$(CC) $(INC) -o my_dump $^ $(LIBS)pcap
	@echo "Created mydump"
	@echo "Running mydump"

.PHONY: clean

clean:
	$(AT)rm -f $(ODIR)/*.o
	$(AT)rm -rf $(ODIR)
	$(AT)rm -rf my_dump
run:
	sudo ./my_dump

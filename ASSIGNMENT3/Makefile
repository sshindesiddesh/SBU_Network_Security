CC=gcc
LIBS=-l
SDIR=src
ODIR=obj
AT=@
INC=-Iinclude

SRCS:=$(wildcard $(SDIR)/*.c)
OBJS=$(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(SRCS))
	
$(ODIR)/%.o: $(SDIR)/%.c
	$(AT)mkdir -p $(ODIR)
	$(AT)$(CC) $(INC) -c $< -o $@ $(LIBS)crypto

all: $(OBJS)
	$(AT)$(CC) $(INC) -o pbproxy $^ $(LIBS)crypto $(LIBS)pthread

clean:
	$(AT)rm -f $(ODIR)/*.o
	$(AT)rm -rf $(ODIR)
	$(AT)rm -rf pbproxy
run:
	sudo ./my_dump

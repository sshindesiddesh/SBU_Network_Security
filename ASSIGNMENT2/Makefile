CC=g++
INC = -I incl
LIBS = -lm
SDIR=src
ODIR=bin
AT=@

_OBJS = *.o
OBJS = $(patsubst %,$(ODIR)/%,$(_OBJS))

$(ODIR)/%.o: $(SDIR)/%.cpp
	$(AT)mkdir -p $(ODIR)
	$(AT)$(CC) -c $(INC) $< -o $@ $(CFLAGS)

all: $(OBJS)
	$(AT)$(CC) -o my_dump $^

.PHONY: clean

clean:
	$(AT)rm -f $(ODIR)/*.o
	$(AT)rm -rf $(ODIR)
	$(AT)rm -rf my_dump

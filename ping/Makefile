#######################################
#  Makefile for the ping program.     #
#  For: Computer Networks course.     #
#######################################

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic -I..
LDFLAGS = -lm

RM = rm -f

# Headers
HEADERS = net_utils.h

# Sources
OBJS = ping.o net_utils.o

ping.o: ping.c ../net_utils.h
	$(CC) $(CFLAGS) -c ping.c

net_utils.o: ../net_utils.c ../net_utils.h
	$(CC) $(CFLAGS) -c ../net_utils.c -o net_utils.o


# Executable
EXECS = ping

# Default arguments
IP = 1.1.1.1
COUNT = 4

.PHONY: all default clean runp runpc runpf runpfc runsp

all: $(EXECS)
default: all


############
# Programs #
############

$(EXECS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)


################
# Run programs #
################

# Run ping program in sudo mode (default: infinite)
runp: $(EXECS)
	sudo ./$< -a $(IP)

# Run ping with count (-c)
runpc: $(EXECS)
	sudo ./$< -a $(IP) -c $(COUNT)

# Run ping with flood (-f)
runpf: $(EXECS)
	sudo ./$< -a $(IP) -f

# Run ping with count + flood
runpfc: $(EXECS)
	sudo ./$< -a $(IP) -c $(COUNT) -f


################
# System Trace #
################

# System trace for default mode
runsp: $(EXECS)
	sudo strace ./$< -a $(IP)


################
# Object files #
################

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@


#################
# Cleanup files #
#################

clean:
	$(RM) *.o *.so $(EXECS)
#########################################
#  Makefile for the traceroute program  #
#  For: Computer Networks course.       #
#########################################

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic -I..
LDFLAGS = -lm

RM = rm -f

# Headers
HEADERS = net_utils.h

# Sources
OBJS = traceroute.o net_utils.o

traceroute.o: traceroute.c ../net_utils.h
	$(CC) $(CFLAGS) -c traceroute.c

net_utils.o: ../net_utils.c ../net_utils.h
	$(CC) $(CFLAGS) -c ../net_utils.c -o net_utils.o

# Executable
EXECS = traceroute

# Default arguments
IP = 8.8.8.8

.PHONY: all default clean runtr runs

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

# Run traceroute program in sudo mode
runtr: $(EXECS)
	sudo ./$< -a $(IP)


################
# System Trace #
################

# System trace for traceroute
runs: $(EXECS)
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
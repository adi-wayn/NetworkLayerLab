#######################################
# 	Makefile for the ping program.    #
#	For: Computer Networks course.    #
#	Free to use and distribute.       #
#######################################

# Use the gcc compiler.
CC = gcc

# Flags for the compiler. Can also use -g for debugging.
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic

# Command to remove files.
RM = rm -f

# Header files.
HEADERS = ping.h

# Executable files.
EXECS = ping

# IP address to ping.
IP = 1.1.1.1

# Phony targets - targets that are not files but commands to be executed by make.
.PHONY: all default clean runp runsp

# Default target - compile everything and create the executables and libraries.
all: $(EXECS)

# Alias for the default target.
default: all


############
# Programs #
############

# Compile the ping program.
$(EXECS): $(EXECS).o
	$(CC) $(CFLAGS) -o $@ $^


################
# Run programs #
################

# Run ping program in sudo mode.
runp: $(EXECS)
	sudo ./$< $(IP)

################
# System Trace #
################

# Run the ping program with system trace (sudo mode).
runsp: $(EXECS)
	sudo strace ./$< $(IP)

################
# Object files #
################

# Compile all the C files into object files.
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


#################
# Cleanup files #
#################

# Remove all the object files, shared libraries and executables.
clean:
	$(RM) *.o *.so $(EXECS)
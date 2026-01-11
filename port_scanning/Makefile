##########################################
#  Makefile for the port_scanning program #
#  For: Computer Networks course          #
##########################################

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -pedantic -I..
LDFLAGS = -lm

RM = rm -f

# ===== Files =====
HEADERS = ../net_utils.h

# אם הקובץ שלך נקרא אחרת - תשני פה
OBJS = port_scanning.o net_utils.o

# Executable name
EXECS = port_scanning

# Default arguments
IP = 8.8.8.8
TYPE = TCP

.PHONY: all default clean run_tcp run_udp

all: $(EXECS)
default: all

############
# Compile  #
############

# קימפול הקובץ של הסורק (בתיקייה הנוכחית)
port_scanning.o: port_scanning.c $(HEADERS)
	$(CC) $(CFLAGS) -c port_scanning.c -o port_scanning.o

# קימפול net_utils.c מהשורש (אצלך זה בשורש הפרויקט)
net_utils.o: ../net_utils.c $(HEADERS)
	$(CC) $(CFLAGS) -c ../net_utils.c -o net_utils.o

############
# Link     #
############

$(EXECS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

############
# Run      #
############

run_tcp: $(EXECS)
	sudo ./$(EXECS) -a $(IP) -t TCP

run_udp: $(EXECS)
	sudo ./$(EXECS) -a $(IP) -t UDP

############
# Clean    #
############

clean:
	$(RM) *.o $(EXECS)

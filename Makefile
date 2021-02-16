CFLAGS=-W -Wall -Werror -Wextra -pedantic -O3 -march=native -std=c11
OBJS=main.o pt-aes.o
APP=pt-aes-test

.PHONY=all clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) -o $(APP) $(CFLAGS) $(OBJS)

clean:
	$(RM) -f $(OBJS)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

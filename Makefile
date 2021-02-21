CFLAGS=-W -Wall -Werror -Wextra -pedantic -O3 -march=native -std=c11
# uncomment to enable mix_col and inv_mix_col tests
# CFLAGS+=-DPT_AES_TEST
OBJS=main.o pt-aes.o
APP=pt-aes-test

.PHONY=all clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) -o $(APP) $(CFLAGS) $(OBJS)

clean:
	$(RM) -f $(OBJS) $(APP)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

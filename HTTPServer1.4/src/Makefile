CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/include/postgresql -I/usr/include/json-c

OBJ = main.o http_server.o config.o log.o auth.o
LIBS = -lpq -ljson-c

http_server: $(OBJ)
	$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) http_server


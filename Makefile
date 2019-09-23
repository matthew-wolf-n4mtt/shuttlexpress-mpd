CFLAGS = -Wall

all: shuttlexpress-mpd

shuttlexpress-mpd: shuttlexpress-mpd.o
	$(CC) shuttlexpress-mpd.o -o shuttlexpress-mpd -lmpdclient

clean:
	rm -f *.o shuttlexpress-mpd

%.0:	%.c
	$(CC) -c $< -o $@

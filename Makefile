CFLAGS = -g -Wall

#all: alsalibtest tinyalsatest
#all: clean wovapp

#alsalibtest: alsalib-test.o
#	$(CC) $(CFLAGS) alsalib-test.o -o alsalib-test -lasound

#alsactltest: alsactl-test.o
#	$(CC) $(CFLAGS) alsactl-test.o -o alsactl-test -lasound

#tinyalsatest: tinyalsa-test.o
#	$(CC) $(CFLAGS) tinyalsa-test.o -o tinyalsa-test -ltinyalsa

#wovapp: wovapp.o
all:	wovapp.o
	$(CC) $(CFLAGS) wovapp.o -o wovapp -lasound -lm
clean:
	-rm  wovapp *.o

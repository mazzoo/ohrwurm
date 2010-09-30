CC=gcc

all: ohrwurm

ohrwurm: ohrwurm.c
	$(CC) -Wall -o $@ $^ -lpcap


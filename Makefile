EXE = proj
IN = puissant.c
DOUT = decrypt

all:
	gcc -ansi -O3 $(IN) -o $(EXE)

clean:
	rm $(EXE) $(DOUT)

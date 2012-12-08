all: binaryEncryption

binaryEncryption: ws-cryptoLibHash.o ws-cryptoLibEnc.o
	g++ -o cryptoUtil ws-cryptoLibEnc.o ws-cryptoLibHash.o ../binaryEncryption.cpp -m32 -static-libstdc++ -static-libgcc

ws-cryptoLibHash.o:
	nasm -f elf ../ws-cryptoLibHash.nasm -o ws-cryptoLibHash.o

ws-cryptoLibEnc.o:
	nasm -f elf ../ws-cryptoLibEnc.nasm -o ws-cryptoLibEnc.o

clean:
	rm -rf *o binaryEncryption
nasm -f win32 --prefix _ ../ws-cryptoLibEnc.nasm -o ws-cryptoLibEnc.o

nasm -f win32 --prefix _ ../ws-cryptoLibHash.nasm -o ws-cryptoLibHash.o


g++ -g -m32 -o crypto.exe ../binaryEncryption.cpp ws-cryptoLibEnc.o ws-cryptoLibHash.o -static-libstdc++ -static-libgcc

del *.o
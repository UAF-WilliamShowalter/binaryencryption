William Showalter
CS 301 - Enhanced Encryption Program
Development Platform: Mac OSX 10.8.1
Development Environment: Xcode 4.5, with Clang C++ Compiler and built in NASM


This is a 32bit program to perform encryption on data read in from a file.

Users are prompted for their selection of encryption or decryption, and then for the paths to the files that contain the data, the key to be used, and the location of the output file.

A series of assembly xor's and circular bit shifts are performed on 32bit (4byte) sections of the data to perform the encryption/decryption.

Features include: Checksum stored in the encrypted data for checking integrity of decrypted data. File paths are checked and will reprompt if unaccessible.
                  Calculates how fast data is processed being encrypted or decrypted. Read time for key creates overhead, key chunks are potentially the same size of data for each read.
                  This is the speed at which it took to load the data, key, run the encryption/decryption function, and write out to file the result.
                  
One 4 byte checksum is inserted into encrypted data for every MAX_FILE_SIZE piece of the file. MAX_FILE_SIZE is currently 1MB.

INSTALLATION NOTES:
To install on Linux, run "make" in the linux/ directory. It will build a cryptoUtil binary file to execute.
To install on Mac, run "make" in the macosx/ directory. It will build a cryptoUtil binary file to execute.
To install on Windows, just use the crypto.exe executable. If you really want, and have g++.exe & nasm.exe in your system path, you can use make.bat and it will compile you a new executable with the included source files.



Written by William Showalter. williamshowalter@gmail.com.
Date Last Modified: 14 December 2012
Created: November 2012

Released under Creative Commons - creativecommons.org/licenses/by-nc-sa/3.0/
Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)

Includes time code written by Dr. Orion Sky Lawlor, lawlor@alaska.edu, in "NetRunlib.h"
Code written in NetRunlib.h remains the copyright of Dr. Orion Sky Lawlor.

**NOTE**
   I am not a crytologist/cryptanalyst and have not analysed this encryption algorithm for security.
	   Some implementation choices may very well lower security.

** DO NOT expect actual security if you choose to encrypt actual data using this.

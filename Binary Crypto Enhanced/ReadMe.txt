William Showalter
CS 301 - Enhanced Encryption Program
Development Platform: Mac OSX 10.8.1
Development Environment: Xcode 4.5, with Clang C++ Compiler and built in NASM


This is a 32bit program to perform encryption on data read in from a file.

Users are prompted for their selection of encryption or decryption, and then for the paths to the files that contain the data, the key to be used, and the location of the output file.

A series of assembly xor's and circular bit shifts are performed on 32bit (4byte) sections of the data to perform the encryption/decryption.

Features include: Checksum stored in the encrypted data for checking integrity of decrypted data. File paths are checked and will reprompt if unaccessible.
				  Calculates how fast data is processed being encrypted or decrypted. A large key file will create significant overhead. 
					This is the speed at which it took to load the data, key, run the encryption/decryption function, and write out to file the result.


Written by William Showalter. williamshowalter@gmail.com.
Date Last Modified: 5 December 2012
Created: November 2012

Includes time code written by Dr. Orion Sky Lawlor, lawlor@alaska.edu, in "NetRunlib.h"

**NOTE**
   I am not a crytologist/cryptanalyst and have not analysed this encryption algorithm for security.
	   Some implementation choices may very well lower security.

** DO NOT expect actual security if you choose to encrypt actual data using this.

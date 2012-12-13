/*
    This is a 32bit program to perform encryption on data read in from a file.

    Users are prompted for their selection of encryption or decryption, and then for the paths to the files that contain the data, the key to be used, and the location of the output file.
    
    A series of assembly xor's and circular bit shifts are performed on 32bit (4byte) sections of the data to perform the encryption/decryption.
 
    Features include: Checksum stored in the encrypted data for checking integrity of decrypted data. File paths are checked and will reprompt if unaccessible.
                      Calculates how fast data is processed being encrypted or decrypted. Read time for key creates overhead. Key is only read once and limited to effective size of 512MB.
                      This is the speed at which it took to load the data, key, run the encryption/decryption function, and write out to file the result.

 
    Written by William Showalter. williamshowalter@gmail.com.
    Date Last Modified: 9 December 2012
    Created: November 2012
 
    Released under Creative Commons - creativecommons.org/licenses/by-nc-sa/3.0/
    Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)
 
    Includes time code written by Dr. Orion Sky Lawlor. lawlor@alaska.edu
    in "NetRunlib.h" Code written in NetRunlib.h remains the copyright of Dr. Orion Sky Lawlor.
 
    **NOTE**
       I am not a crytologist/cryptanalyst and have not analysed this encryption algorithm for security.
           Some implementation choices may very well lower security.

    ** DO NOT expect actual security if you choose to encrypt actual data using this.


*/

#include <cstdlib>		// Exit, misc.
#include <fstream>      // File IO operations
#include <iostream>     // Reading input, prompt user
#include <stdexcept>    // May throw during encyption or decryption, if files can't be opened
#include <string>       // std::string and std::getline for user input.
#include <vector>       // STL Container std::vector

#include "NetRunlib.h"  // time_in_seconds function

// GLOBAL CONSTANTS
const unsigned int BIT_SHIFT_COUNT = 16;              // Multiple of 8 (full byte increments)
const unsigned int MAX_FILE_SIZE = 1024 * 1024 * 512; // Maximum vector size without getting bad_alloc on insert. 1MB
enum OPERATION {ENCRYPT = 0, DECRYPT = 1};
enum BYTES {BYTES = 0, KILOBYTES = 1, MEGABYTES = 2, GIGABYTES = 3};

// Assembly functions for performing encryption & hashing. In source files "ws-cryptoLibEnc.nasm" and "ws-cryptoLibHash.nasm".
extern "C" int encryptionAlgorithm(unsigned int *, unsigned int *, unsigned int *, unsigned int *, OPERATION);
extern "C" int hashingAlgorithm (unsigned int *, unsigned int *);

// Function Prototypes
void                            menu ();
unsigned int                    encryption(std::string datafilename, std::string keyfilename, std::string outputname);
std::pair<unsigned int,bool>    decryption(std::string datafilename, std::string keyfilename, std::string outputname);
void                            timePrint (double time1, double time2, int dataSize);
void                            testDriver (std::string datafilename, std::string outputfilename, std::string keyfilename, std::string tempOutputname);

int main(int argc, const char * argv[])
{
    std::cout << "WS Binary Encryption Utility\n\n";
    menu();
    
    
    // Example testing driver calls:
    //testDriver ("/Users/William/Desktop/input.pdf", "/Users/William/Desktop/output.pdf", "/Users/William/Desktop/key.pdf", "/Users/William/Desktop/tempOutput");
    //testDriver ("/Users/William/Desktop/input.mkv", "/Users/William/Desktop/output.mkv", "/Users/William/Desktop/key.mkv", "/Users/William/Desktop/tempOutput");
    
    return 0;
}

void menu ()
{
    /*
     This function runs a loop to prompt the user for input.
     
     Menu loop prompts are:
     1. Encryption
     2. Decryption
     3. Exit
     
     Options 1 & 2 will ask for input, key, and output file paths.
     
     Will reprompt if file paths are invalid.
     */
    
    
    
    // Paths to our input files
    
    std::string inputfilepath;
    std::string keyfilepath;
    std::string outputfilepath;
    
    // Menu Code - pretty much self documenting switch statements.
    int menuselection;
    while (true)
    {
        std::cout   << "Please make a selection:\n"
        << "1. Encryption\n" << "2. Decryption\n" << "3. Exit\n" << "Selection #: ";
        std::cin    >> menuselection;
        
        std::cin.ignore(); // Getline will read the last line return and not read in any data without an ignore.
        
        switch (menuselection)
        {
            case (1): // Encryption
            {
                std::cout   << std::endl << "Please input the path to the file to be encrypted:\n";
                std::getline (std::cin, inputfilepath);
                
                std::cout   << std::endl << "Please input the path to the key file:\n";
                std::getline (std::cin, keyfilepath);
                
                std::cout   << std::endl << "Please input a path for the output file\n";
                std::getline (std::cin, outputfilepath);
                
                std::cout   << std::endl;
                try {
                    double t1 = time_in_seconds();
                    int dataSize = encryption(inputfilepath, keyfilepath, outputfilepath);
                    double t2 = time_in_seconds();
                    
                    timePrint (t1, t2, dataSize);
                }
                
                catch (std::runtime_error e) {
                    std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
                }
                
                catch (std::bad_alloc e) {
                    std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
                }
                
                catch (...) {
                    std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
                }
                break;
                
                break;
            }
                
            case (2):
            {
                std::cout   << std::endl << "Please input the path to the file to be decrypted:\n";
                std::getline (std::cin, inputfilepath);
                
                std::cout   << std::endl << "Please input the path to the key file:\n";
                std::getline (std::cin, keyfilepath);
                
                std::cout   << std::endl << "Please input a path for the output file\n";
                std::getline (std::cin, outputfilepath);
                
                std::cout   << std::endl;
                
                try
                {
                    double t1 = time_in_seconds();
                    std::pair<unsigned int,bool> decryptionPair = decryption(inputfilepath, keyfilepath, outputfilepath);
                    double t2 = time_in_seconds();
                    
                    timePrint (t1, t2, decryptionPair.first);
                    
                    if (decryptionPair.second)
                        std::cout << std::endl << "Successfully decrypted - checksum matched" << std::endl << std::endl;
                    else
                        std::cout << std::endl << "Unsuccessful decryption - checksum failed" << std::endl << std::endl;
                }
                
                catch (std::runtime_error e) {
                    std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
                }
                
                catch (std::bad_alloc e) {
                    std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
                }
                
                catch (...) {
                    std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
                }
                break;
            }
                
            case (3):
            {
                exit(0);
            }
            default:
            {
                std::cout << "Please choose from the choices below:\n";
            }
        }
    }
}


unsigned int encryption (std::string datafilename, std::string keyfilename, std::string outputname)
{
    /*
     Reads in data and key from file paths passed in. Hashes data into checksum, 
     Encrypts data+checksum and writes out to output path passed in.
     
     Returns the size of the data file encrypted.
     
     Throws exception if filepaths cannot be opened.
     */
    
    std::vector<unsigned int> data;
    std::vector<unsigned int> key;
    unsigned long long dataLength = 0;
    unsigned long long keyLength = 0;
    unsigned long long dataLeft = 0;
    
    // Data is broken into 4 byte chunks (ints, register size), last 4 byte chunk might contain less than 4 bytes of data.
    // finalByteCount contains the number of bytes that contain data in the last 4 byte chunk
    unsigned int finalByteCount = 0;
    
    std::fstream datafilestream;
    std::fstream keyfilestream;
    std::fstream outfilestream;
    
    // Input file & output file cannot be equal.
    if (datafilename == outputname)
        throw std::runtime_error ("INPUT FILE CANNOT EQUAL OUTPUT FILE");
    
    // Open key file
    keyfilestream.open (keyfilename.c_str(), std::ios::in | std::ios::binary);
    if (!keyfilestream.is_open())
        throw (std::runtime_error("Could not open key file. Check that directory path is valid."));
    
    // Open data file
    datafilestream.open (datafilename.c_str(), std::ios::in | std::ios::binary);
    if (!datafilestream.is_open())
        throw (std::runtime_error("Could not open data file. Check that directory path is valid."));
    
    // Open output file
    outfilestream.open (outputname.c_str(), std::ios::out | std::ios::binary);
    if (!outfilestream.is_open())
        throw (std::runtime_error("Could not open output file. Check that directory path is valid."));
    
    // Read in key - Maximum of MAX_FILE_SIZE.
    
    // Find length of key file
    keyfilestream.seekg(0,std::ios::end);
    keyLength = keyfilestream.tellg();
    keyfilestream.clear();
    keyfilestream.seekg(0, std::ios::beg);
    
    if (keyLength < MAX_FILE_SIZE)
    {
        keyLength = (keyLength - keyLength%4);
        key.resize (keyLength/4);
        keyfilestream.read((char*)&key[0],keyLength);
    }
    else
    {
        key.resize (MAX_FILE_SIZE/4);
        keyfilestream.read((char*)&key[0],MAX_FILE_SIZE);
    }

    keyfilestream.close();

    // Encryption Loop
    
    datafilestream.seekg(0, std::ios::end);
    dataLength = datafilestream.tellg();
    datafilestream.clear();
    datafilestream.seekg(0, std::ios::beg);
    
    dataLeft = dataLength;
    
    while (!datafilestream.fail())
    {
        
        if (dataLeft <= MAX_FILE_SIZE-4)
        {
            // +1 is for hash, if mod ++ is in case division truncated dataLength
            unsigned long long resizeAmmount = dataLeft/4 + 1;
            if (dataLeft%4)
                resizeAmmount++;
            
            data.resize (resizeAmmount);
            
            // Max file size read will go off end, setting fail bit, and preventing the loop from running again.
            datafilestream.read((char*)&data[1], MAX_FILE_SIZE);
            finalByteCount = dataLength % 4;
            if (!finalByteCount)
                finalByteCount = 4;
        }
        
        else
        {
            data.resize (MAX_FILE_SIZE/4);
            datafilestream.read((char*)&data[1],MAX_FILE_SIZE-4);
        }
                
        // Compute Hash
        unsigned int hash = hashingAlgorithm (&data[1], &data[data.size()]);
        data[0] = hash;
        
        // Encrypt
        // vector.begin() & vector.end() will work on some compilers, but iterators may be implemented as a class, which wouldn't be compatible with the assembly function.
        encryptionAlgorithm (&data[0], &data[data.size()], &key[0], &key[key.size()], ENCRYPT);
        
        // Write out to file
        
        if (dataLeft <= MAX_FILE_SIZE - 4)
        {
            data[data.size()-1] = (data[data.size()-1]<<(BIT_SHIFT_COUNT)) + (data[data.size()-1]>>(32 - BIT_SHIFT_COUNT));
            outfilestream.write((char*)&data[0], dataLeft+4); // Adjust for checksum.
        }
        
        else
        {
            outfilestream.write ((char*)&data[0], MAX_FILE_SIZE);
            dataLeft -= (MAX_FILE_SIZE - 4);
        }
        
        data.clear();
    }

    datafilestream.close();
    outfilestream.close();

    // Overwrite key from memory before it is unallocated.
    for (unsigned int * iter = &(key[0]); iter != &(key[key.size()]); iter+=4)
    {
        *iter = 0xFFFFFFFF;
    }
    
    return dataLength;
}

std::pair<unsigned int,bool> decryption (std::string datafilename, std::string keyfilename, std::string outputname)
{
    /*
     Reads in encrypted data and key from file paths passed in. Decrypts encrypted data,
     pulls out pre-encrypted checksum & computes checksum of now decrypted data.
     Writes out decrypted data to output path.
     
     Returns pair of int & bool. Int is the size of the data read in, and the bool is based on the comparison of the checksums, to see if they're equal.
     
     Throws std::runtime_error exception if filepaths cannot be opened.
     */
    
    std::vector<unsigned int> data;
    std::vector<unsigned int> key;
    std::vector<unsigned int> hashesBefore;
    std::vector<unsigned int> hashesAfter;
    unsigned long long dataLength = 0;
    unsigned long long keyLength = 0;
    unsigned long long dataLeft = 0;
    bool checksum;
    
    // Data is broken into 4 byte chunks (ints, register size), last 4 byte chunk might contain less than 4 bytes of data.
    // finalByteCount contains the number of bytes that contain data in the last 4 byte chunk
    unsigned int finalByteCount = 0;
    
    std::fstream datafilestream;
    std::fstream keyfilestream;
    std::fstream outfilestream;
    
    // Input file cannot equal output file
    if (datafilename == outputname)
        throw (std::runtime_error("INPUT FILE CANNOT EQUAL OUTPUT FILE"));
    
    // Open key file
    keyfilestream.open (keyfilename.c_str(), std::ios::in | std::ios::binary);
    if (!keyfilestream.is_open())
        throw (std::runtime_error("Could not open key file. Check that directory path is valid."));
    
    // Open data file
    datafilestream.open (datafilename.c_str(), std::ios::in | std::ios::binary);
    if (!datafilestream.is_open())
        throw (std::runtime_error("Could not open data file. Check that directory path is valid."));
    
    // Open output file
    outfilestream.open (outputname.c_str(), std::ios::out | std::ios::binary);
    if (!outfilestream.is_open())
        throw (std::runtime_error("Could not open output file. Check that directory path is valid."));
    
    // Read in key - Maximum of MAX_FILE_SIZE.
    
    // Find length of key file
    keyfilestream.seekg(0,std::ios::end);
    keyLength = keyfilestream.tellg();
    keyfilestream.seekg(0, std::ios::beg);
    
    if (keyLength < MAX_FILE_SIZE)
    {
        keyLength = (keyLength - keyLength%4);
        key.resize (keyLength/4);
        keyfilestream.read((char*)&key[0],keyLength);
    }
    
    else
    {
        key.resize (MAX_FILE_SIZE/4);
        keyfilestream.read((char*)&key[0],MAX_FILE_SIZE);
    }
    
    keyfilestream.close();
    
    // Decryption Loop
    
    datafilestream.seekg(0, std::ios::end);
    dataLength = datafilestream.tellg();
    datafilestream.clear();
    datafilestream.seekg(0, std::ios::beg);
    
    dataLeft = dataLength;
    
    while (!datafilestream.fail())
    {
        // Reads encrypted data into vector in four byte blocks, doing MAX_FILE_SIZE at a time, last value may contain less than 4 bytes. Actual length recorded in finalByteCount.
        if (dataLeft <= MAX_FILE_SIZE)
        {
            // if mod ++ is in case division truncated dataLength
            unsigned long long resizeAmmount = dataLeft/4;
            if (dataLeft%4)
                resizeAmmount++;
            
            data.resize (resizeAmmount);
            
            // Max file size + 1 read will go off end, setting fail bit, and preventing the loop from running again.
            datafilestream.read((char*)&data[0], MAX_FILE_SIZE+1);
            finalByteCount = dataLength % 4;
            if (!finalByteCount)
                finalByteCount = 4;
            
            // Shift last section back into original placement.
            data[data.size()-1] = ((data[data.size()-1]>>(BIT_SHIFT_COUNT))+(data[data.size()-1]<<(32 - BIT_SHIFT_COUNT)));
            
        }
        
        else
        {
            data.resize (MAX_FILE_SIZE/4);
            datafilestream.read((char*)&data[0],MAX_FILE_SIZE);
        }
    
        // Decrypt
        encryptionAlgorithm (&data[0], &data[data.size()], &key[0], &key[key.size()], DECRYPT);
        
        // Check hashes
        hashesBefore.push_back(*(data.begin()));
        
        data.erase(data.begin());
        
        // Removes unsignificant bits that were originally 0, but only if we hit end of file this round.
        if (finalByteCount != 0)
            (*(data.end()-1))=((*(data.end()-1))&(~(0xFFFFFFFF<<(8*finalByteCount))));
        
        hashesAfter.push_back(hashingAlgorithm (&data[0], &data[data.size()]));
        
        // Write out to file
        
        if (dataLeft <= MAX_FILE_SIZE)
        {
            data[data.size()-1] = (data[data.size()-1]<<(BIT_SHIFT_COUNT)) + (data[data.size()-1]>>(32 - BIT_SHIFT_COUNT));
            outfilestream.write((char*)&data[0], dataLeft - 4); // Adjust for checksum
        }
        
        else
        {
            outfilestream.write ((char*)&data[0], MAX_FILE_SIZE-4);
            dataLeft -= (MAX_FILE_SIZE);
        }
        
        data.clear();
    }
    
    datafilestream.close();
    outfilestream.close();
    
    // Overwrite key from memory before it is unallocated.
    for (unsigned int * iter = &(key[0]); iter != &(key[key.size()]); iter+=4)
    {
        *iter = 0xFFFFFFFF;
    }
    
    unsigned int hashBefore = hashingAlgorithm(&hashesBefore[0],&hashesBefore[hashesBefore.size()]);
    unsigned int hashAfter = hashingAlgorithm(&hashesAfter[0],&hashesAfter[hashesAfter.size()]);
    
    checksum = (hashBefore == hashAfter);
    
    return std::pair<unsigned int,bool>(dataLength,checksum);  // Return size of data & Return true if decryption matches the hash.
}

void timePrint (double time1, double time2, int dataSize)
{
    /*
     Calculates and prints to console the data speed of a given operation.
     
     time1 & time2 are the times before and after the operation.
     dataSize is the size (in 4 byte chunks) of the data operated on.
     
     */
    
    int byteCounter = 0;
    
    double bytesPerSecond = (dataSize * 4)/(time2-time1);
    
    if (bytesPerSecond > 1024)
    {
        byteCounter = KILOBYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }
    
    if (bytesPerSecond > 1024)
    {
        byteCounter = MEGABYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }
    
    if (bytesPerSecond > 1024)
    {
        byteCounter = GIGABYTES;
        bytesPerSecond = bytesPerSecond / 1024;
    }
    
    std::string byteUnits;
    switch (byteCounter)
    {
        case (BYTES):
            byteUnits = "B/s";
            break;
        case (KILOBYTES):
            byteUnits = "KB/s";
            break;
        case (MEGABYTES):
            byteUnits = "MB/s";
            break;
        default: 
            byteUnits = "GB/s";
    }
    
    std::cout << "\n Processed at an average rate of: " << bytesPerSecond << " " << byteUnits << std::endl << std::endl;
    
}

void testDriver (std::string datafilename, std::string outputfilename, std::string keyfilename, std::string tempOutputname)
{
    /*
         Test Function for use when application features/implementation is being worked on.
         Uses much of the menu code for performance measuring and error handling.
         Performs encryption and subsequent decryption of specified input.
         
     */

    // Encryption
    std::cout   << std::endl;
    try {
        double t1 = time_in_seconds();
        int dataSize = encryption(datafilename, keyfilename, tempOutputname);
        double t2 = time_in_seconds();
        std::cout << "\nEncryption: ";
        timePrint (t1, t2, dataSize);
    }
    
    catch (std::runtime_error e) {
        std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
    }
    
    catch (std::bad_alloc e) {
        std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
    }
    
    catch (...) {
        std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
    }


    // Decryption
    try
    {
        double t1 = time_in_seconds();
        std::pair<unsigned int,bool> decryptionPair = decryption(tempOutputname, keyfilename, outputfilename);
        double t2 = time_in_seconds();
        std::cout << "\nDecryption: ";
        timePrint (t1, t2, decryptionPair.first);
        
        if (decryptionPair.second)
            std::cout << std::endl << "Successfully decrypted - checksum matched" << std::endl << std::endl;
        else
            std::cout << std::endl << "Unsuccessful decryption - checksum failed" << std::endl << std::endl;
    }
    
    catch (std::runtime_error e) {
        std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
    }
    
    catch (std::bad_alloc e) {
        std::cout << "\n\n******\n" << "Allocation Error - Sufficient memory might not be available.\n" << e.what() << "\n******\n\n";
    }
    
    catch (...) {
        std::cout << "\n\n******\n" << "Unspecified Exception Caught: Restarting Menu" << "\n******\n\n";
    }
}
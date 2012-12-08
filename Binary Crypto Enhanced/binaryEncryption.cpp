/*
    This is a 32bit program to perform encryption on data read in from a file.

    Users are prompted for their selection of encryption or decryption, and then for the paths to the files that contain the data, the key to be used, and the location of the output file.
    
    A series of assembly xor's and circular bit shifts are performed on 32bit (4byte) sections of the data to perform the encryption/decryption.
 
    Features include: Checksum stored in the encrypted data for checking integrity of decrypted data. File paths are checked and will reprompt if unaccessible.
                      Calculates how fast data is processed being encrypted or decrypted. A large key file will create significant overhead. 
                        This is the speed at which it took to load the data, key, run the encryption/decryption function, and write out to file the result.

 
    Written by William Showalter. williamshowalter@gmail.com.
    Date Last Modified: 5 December 2012
    Created: November 2012
 
    Includes time code written by Dr. Orion Sky Lawlor. lawlor@alaska.edu
    in "NetRunlib.h"
 
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
const int BIT_SHIFT_COUNT = 16;     // Multiple of 8 (full byte increments)
enum OPERATION {ENCRYPT = 0, DECRYPT = 1};
enum BYTES {BYTES = 0, KILOBYTES = 1, MEGABYTES = 2, GIGABYTES = 3};

// Assembly functions for performing encryption & hashing. In source files "ws-cryptoLibEnc.nasm" and "ws-cryptoLibHash.nasm".
extern "C" int encryptionAlgorithm(unsigned int *, unsigned int *, unsigned int *, unsigned int *, OPERATION);
extern "C" int hashingAlgorithm (unsigned int *, unsigned int *);

// Function Prototypes
void                menu ();
int                 encryption(std::string datafilename, std::string keyfilename, std::string outputname);
std::pair<int,bool> decryption(std::string datafilename, std::string keyfilename, std::string outputname);
void                timePrint (double time1, double time2, int dataSize);

int main(int argc, const char * argv[])
{
    std::cout << "WS Binary Encryption Utility\n\n";
    menu();
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
                    
                } catch (std::runtime_error e) {
                    std::cout << "\n\n******\n" << e.what() << "\n******\n\n";
                } catch (...) {
                    std::cout << "\n\n******\n" << "Exception caught - Possibly one of the specified files was too large to fit in memory." << "\n******\n\n";
                }
                
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
                    std::pair<int,bool> decryptionPair = decryption(inputfilepath, keyfilepath, outputfilepath);
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
                
                catch (...) {
                    std::cout << "\n\n******\n" << "Exception caught - Possibly one of the specified files was too large to fit in memory." << "\n******\n\n";
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


int encryption (std::string datafilename, std::string keyfilename, std::string outputname)
{
    /*
     Reads in data and key from file paths passed in. Hashes data into checksum, 
     Encrypts data+checksum and writes out to output path passed in.
     
     Returns the size of the data file encrypted.
     
     Throws exception if filepaths cannot be opened.
     */
    
    std::vector<unsigned int> data;
    std::vector<unsigned int> key;
    
    // Data is broken into 4 byte chunks (ints, register size), last 4 byte chunk might contain less than 4 bytes of data.
    // finalByteCount contains the number of bytes that contain data in the last 4 byte chunk
    int finalByteCount = 0;
    
    std::fstream filestream;
    
    // Read in data (unencrypted data)
    filestream.open (datafilename.c_str(), std::ios::in | std::ios::binary);
    if (!filestream.is_open())
        throw (std::runtime_error("Could not open data file. Check that directory path is valid."));

    while (!filestream.eof())
    {
        // Reads unencrypted data into vector in four byte blocks, last value may contain less than 4 bytes. Actual length recorded in finalByteCount.
        int temp = 0;
        filestream.read((char*)&temp,4);
        
        if (!filestream.eof())
            data.push_back(temp);
        else
        {
            finalByteCount = filestream.gcount();
            data.push_back(temp);
        }
    }
    
    filestream.close();
    
    // Read in key
    filestream.open (keyfilename.c_str(), std::ios::in | std::ios::binary);
    if (!filestream.is_open())
        throw (std::runtime_error("Could not open key file. Check that directory path is valid."));
    
    while (!filestream.eof())
    {
        // Reads in key. Last 4 byte chunk is not used in the key because it might contain less than 4 bytes (less entropy/predictable/limited set of data).
        // Minimum 4 byte key.
        int temp;
        filestream.read((char*)&temp,4);
        if (!filestream.eof())
            key.push_back(temp);
    }
    
    filestream.close();
    
    // Compute Hash
    unsigned int hash = hashingAlgorithm (&data[0], &data[data.size()]);
    data.insert(data.begin(), hash);
    
    // Encrypt
    // vector.begin() & vector.end() will work on some compilers, but iterators may be implemented as a class, which wouldn't be compatible with the assembly function.
    encryptionAlgorithm (&data[0], &data[data.size()], &key[0], &key[key.size()], ENCRYPT);
    
    // Write out to file
    
    filestream.open (outputname.c_str(), std::ios::out | std::ios::binary);
    if (!filestream.is_open())
        throw (std::runtime_error("Could not open output file. Check that directory path is valid."));
    
    for (std::vector<unsigned int>::iterator ii = data.begin(); ii != (data.end()); ii++)
    {
        // Writes decrypted data out to file. Size of last block of bytes is determined by finalByteCount
        
        int temp;
        temp = *ii;
        
        if ((ii) != (data.end()-1))
        {
            filestream.write((char*)&temp,4);
        }
        
        else
        {
            // Insignificant bits (not from data in the input file) our discared on write out of the last block.
            // They won't decrypt to the same values - but they won't affect the rest of the decryption. Bits are independent of each other in the same block.
            temp = ((temp<<(BIT_SHIFT_COUNT))+(temp>>(32 - BIT_SHIFT_COUNT)));
            filestream.write((char*)&temp,finalByteCount);
        }
    }
    filestream.close();
    
    return data.size();
}

std::pair<int,bool> decryption (std::string datafilename, std::string keyfilename, std::string outputname)
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
    
    // Data is broken into 4 byte chunks (ints, register size), last 4 byte chunk might contain less than 4 bytes of data.
    // finalByteCount contains the number of bytes that contain data in the last 4 byte chunk
    int finalByteCount = 0;
    
    std::fstream filestream;
    
    // Read in data
    filestream.open (datafilename.c_str(), std::ios::in | std::ios::binary);
    if (!filestream.is_open())
        throw (std::runtime_error("Could not open data file. Check that directory path is valid."));
    
    while (!filestream.eof())
    {
        // Reads encrypted data into vector in four byte blocks, last value may contain less than 4 bytes. Actual length recorded in finalByteCount.
        int temp = 0;
        filestream.read((char*)&temp,4);
        
        if (!filestream.eof())
            data.push_back(temp);
        else
        {
            finalByteCount = filestream.gcount();
            temp = ((temp>>(BIT_SHIFT_COUNT))+(temp<<(32 - BIT_SHIFT_COUNT)));
            data.push_back(temp);
        }
    }
    
    filestream.close();
    
    // Read in key
    filestream.open (keyfilename.c_str(), std::ios::in | std::ios::binary);
    if (!filestream.is_open())
        throw (std::runtime_error("Could not open key file. Check that directory path is valid."));
    
    while (!filestream.eof())
    {
        // Reads in key. Last 4 byte chunk is not used in the key because it might contain less than 4 bytes (less entropy/predictable/limited set of data).
        int temp;
        filestream.read((char*)&temp,4);
        if (!filestream.eof())
            key.push_back(temp);
    }
    
    filestream.close();
    
    // Decrypt
    encryptionAlgorithm (&data[0], &data[data.size()], &key[0], &key[key.size()], DECRYPT);
    
    // Check hashes
    unsigned int hash_before = *(data.begin());
    
    data.erase(data.begin());
    
    // Removes unsignificant bits that were originally 0
    (*(data.end()-1))=((*(data.end()-1))&(~(0xFFFFFFFF<<(8*finalByteCount))));
    
    unsigned int hash_after = hashingAlgorithm (&data[0], &data[data.size()]);
    bool checksum = (hash_before == hash_after);
    
    // Write out to file
    filestream.open (outputname.c_str(), std::ios::out | std::ios::binary);
    if (!filestream.is_open())
        throw (std::runtime_error("Could not open output file. Check that directory path is valid."));

    for (std::vector<unsigned int>::iterator ii = data.begin(); ii != (data.end()); ii++)
    {
        // Writes decrypted data out to file. Size of last block of bytes is determined by finalByteCount
        
        int temp;
        temp = *ii;
        
        if ((ii) != data.end()-1)
        {
            filestream.write((char*)&temp,4);
        }
        
        else
        {
            // Low bits that get written out will be the same value. They git shifted back during the decryption process, so no bitshifts are required here.
            filestream.write((char*)&temp,finalByteCount);
        }
    }
    filestream.close();
    
    return std::pair<int,bool>(data.size(),checksum);  // Return size of data & Return true if decryption matches the hash.
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
        case (0):
            byteUnits = "B/s";
            break;
        case (1):
            byteUnits = "KB/s";
            break;
        case (2):
            byteUnits = "MB/s";
            break;
        default:
            byteUnits = "GB/s";
    }
    
    std::cout << "\nProcessed at an average rate of: " << bytesPerSecond << " " << byteUnits << std::endl << std::endl;
    
}
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>

#include <huffman.h>

int main(int argc, char* argv[])
{
    constexpr char USAGE_MSG[] = "Usage: mode input output\n\tmode\t\t-c or -d to compress or decompress respectively"
                                 "\n\tinput\t\tinput file name\n\toutput\t\toutput file name";
    constexpr char COULD_NOT_OPEN_INPUT[] = "Could not open input file";
    constexpr char COULD_NOT_OPEN_OUTPUT[] = "Could not open output file";
    constexpr char INPUT_CORRUPT[] = "Operation could not be done, input file is corrupt";
    constexpr char SUCCESS[] = "Operation done successfully";
    if (argc != 4 || strcmp(argv[1], "-c") != 0 && strcmp(argv[1], "-d") != 0) {
        std::cout << USAGE_MSG << std::endl;
        return 0;
    }
    std::ifstream fin(argv[2]);
    if (!fin) {
        std::cerr << COULD_NOT_OPEN_INPUT << std::endl;
        return -1;
    }
    std::ofstream fout(argv[3]);
    if (!fout) {
        std::cerr << COULD_NOT_OPEN_OUTPUT << std::endl;
        return -1;
    }
    bool encode = std::strcmp(argv[1], "-c") == 0;
    clock_t time = clock();
    if (encode) {
        compress(fin, fout);
    } else {
        try {
            decompress(fin, fout);
        } catch (...) {
            std::cerr << INPUT_CORRUPT << std::endl;
            return -1;
        }
    }
    double elapsed = static_cast<double>(clock() - time) / CLOCKS_PER_SEC;
    std::cerr << SUCCESS << std::endl;
    std::cerr << "Time elapsed: " << std::setprecision(3) << elapsed << " seconds" << std::endl;
    return 0;
}
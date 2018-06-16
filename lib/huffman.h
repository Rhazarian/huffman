#ifndef HUFFMAN_H
#define HUFFMAN_H

#include <iosfwd>

void compress(std::istream& in, std::ostream& out);
void decompress(std::istream& in, std::ostream& out);

#endif //HUFFMAN_H
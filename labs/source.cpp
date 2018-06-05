//
//  source.cpp
//  labs
//
//  Created by Oleksandr Bohutskyi on 03.06.18.
//  Copyright © 2018 BohutskyiOleksandr. All rights reserved.
//

#include "source.hpp"

/**
 * Generates file with all posible byte pairs
 */
void createEncryptFile()
{
    //const uint size(1 << (n*n));
    std::ofstream out("/Users/oleksandr/Documents/Учьоба/X семестр/СВ/labs/labs/fileToEnc.bin", std::ios::binary);
    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 256; j++)
        {
            out.write((char*)(&j),1);
            out.write((char*)(&i), 1);
            
        }
    out.close();
}

u16 round(u16 in, const u16 &key)
{
    in ^= key;
    in = sbox[in & 0xf] | (sbox[(in >> 4) & 0xf] << 4) | (sbox[(in >> 8) & 0xf] << 8) | (sbox[(in >> 12) & 0xf] << 12);
    
    u16 result((in & 1) | (in&(1 << 15)));
    for (int i = 1; i < 15; i++)
    {
        result |= ((in >> i) & 1) << permutation[i];
    }
    return result;
}

u16 invertRound(u16 in, const u16 &key)
{
    in ^= key;
    u16 result( (in & 1) | (in&(1 << 15)));
    for (int i = 1; i < 15; i++)
        result |= ((in >> i) & 1) << permutation[i];
    
    result = invertSBox[result & 0xf] | (invertSBox[(result >> 4) & 0xf] << 4) | (invertSBox[(result >> 8) & 0xf] << 8) | (invertSBox[(result >> 12) & 0xf] << 12);
    return result;
}

u16 heysEncryption(const u16 &in, const short &r, const u16* key)
{
    u16 result(in);
    for (short i = 0; i < r; i++)
        result = round(result, key[i]);
    result ^= key[r];
    return result;
}

void differentialSearch(const u16 &alpha, std::map<u16, float> &out, const int &r)
{
    std::cout << "Differential Search was started.\n";
    int size(1 << (n*n));
    std::vector<float> frequencies(size, 0);
    std::map<u16,float> previous;
    previous.insert(std::pair<u16,float>(alpha, 1.0));
    float bounds[] = {0.2, 0.02, 0.003, 0.0003, 0.00003};
    
    std::ofstream fout("/Users/oleksandr/Documents/Учьоба/X семестр/СВ/labs/labs/differentials.txt");
    
    for (short i = 0; i < r; i++)
    {
        out.clear();
        for (auto b = previous.begin(); b != previous.end(); ++b)
        {
            calculateProbabilities((*b).first, frequencies);
            for (uint g = 1; g < size; g++)
            {
                auto iterG = out.find(g);
                if (iterG != out.end())
                    (*iterG).second += frequencies[g] * (*b).second;
                else
                    out.insert(std::pair<u16, float>(g, frequencies[g] * (*b).second));
                frequencies[g] = 0;
            }
        }
        previous.clear();
        fout << "round " << i << std::endl;
        for (auto g = out.begin(); g != out.end(); g++)
        {
            if ((*g).second > bounds[i])
            {
                previous.insert(std::pair<u16, float>((*g).first, (*g).second));
                fout << std::hex << (*g).first<<' ';
                fout << (*g).second << std::endl;
            }
        }
    }
    fout.close();
    out = previous;
    std::cout << "Differential Search was completed.\n";
}

/**
 * For the given input difference calculates all possible output differences with probabilities
 */
void calculateProbabilities(const u16 &alpha,std::vector<float> &frequency)
{
    static uint size(1 << (n*n));
    static bool is_encrypted(0);
    static std::vector<u16> encrypted(size,0);
    if (!is_encrypted)
    {
        for (int i = 0; i < size; ++i)
            encrypted[i] = round(i);
        is_encrypted = 1;
    }
    
    for (uint x = 0; x < size; ++x)
        frequency[encrypted[x] ^ encrypted[x^alpha]] += 1;
    for (int b = 1; b < size; b++)
        frequency[b] /= (size - 1);
}

void attack(const u16 &alpha, std::map<u16, float> &differentials)
{
    std::cout << "Attack was started.\n";
    if (differentials.empty())
    {
        std::cout << "Differentials not found.\n" << std::endl;
        return;
    }
    
    const uint size(1 << (n*n));
    u16 data[size];
    std::ifstream in("/Users/oleksandr/Documents/Учьоба/X семестр/СВ/labs/labs/ct1.bin", std::ios::binary);
    char high, low;
    for (int i = 0; i < size; i++)
    {
        in.read(&low, 1);
        in.read(&high, 1);
        data[i] = (low & 0xff) | ((high & 0xff) << 8);
    }
    in.close();
    
    std::vector<int> frequency(size, 0);
    u16 b;
    int num;
    
    //search differential with all not null tetrads
    for (auto beta = differentials.begin(); beta != differentials.end(); beta++)
    {
        b = (*beta).first;
        if ((b & 0xf) && ((b >> 4) & 0xf) && ((b >> 8) & 0xf) && (b >> 12))
        {
            //ciphertexts number
            num = 25000;
            break;
        }
    }

    for (uint k = 1; k < size; k++)
    {
        for (uint i = 0; i < num; i++)
        {
            if ((invertRound(data[i], k) ^ invertRound(data[i^alpha], k)) == b)
                frequency[k]++;
        }
    }
    std::ofstream out("/Users/oleksandr/Documents/Учьоба/X семестр/СВ/labs/labs/keys.txt");
    for (int k = 1; k < size; k++)
    {
        if (frequency[k] >= 5)
            out << std::hex << k << " " << frequency[k] << std::endl;
    }
    out.close();
    std::cout << "Attack was completed.\n";
}

void runScenario()
{
    std::map<u16, float> output;
    differentialSearch(0xf000, output);
    attack(0xf000, output);
}


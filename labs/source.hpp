//
//  source.hpp
//  labs
//
//  Created by Oleksandr Bohutskyi on 03.06.18.
//  Copyright © 2018 BohutskyiOleksandr. All rights reserved.
//

#ifndef source_hpp
#define source_hpp

#include <stdio.h>

#endif /* source_hpp */
#pragma once
#include<iostream>
#include<fstream>
#include<vector>
#include<map>

using uint = unsigned int;
using u16 = unsigned short;
const uint n = 4;
const unsigned char sbox[] = { 0xa,0x9,0xd,0x6,0xe,0xb,0x4,0x5,0xf,0x1,0x3,0xc,0x7,0x0,0x8,0x2 };
const unsigned char invertSBox[]= { 0xd,0x9,0xf,0xa,0x6,0x7,0x3,0xc,0xe,0x1,0x0,0x5,0xb,0x2,0x4,0x8 };
const unsigned char permutation[] = { 0x0,0x4,0x8,0xc,0x1,0x5,0x9,0xd,0x2,0x6,0xa,0xe,0x3,0x7,0xb,0xf };

void createFileToEncrypt();
u16 round(u16 in, const u16 &key = 0);
u16 invertRound(u16 in, const u16 &key = 0);
void calculateProbabilities(const u16 &alpha, std::vector<float> &frq);
void differentialSearch(const u16 &alpha, std::map<u16, float> &out, const int &r = 5);
void attack(const u16 &alpha, std::map<u16, float> &differentials);
u16 heysEncryption(const u16 &in, const short &r, const u16* key);
void runScenario();

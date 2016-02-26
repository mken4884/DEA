#include "DEA.h"

DEA::DEA()
{

}

DEA::~DEA()
{

}

void DEA::encrypt()
{

}

void DEA::decrypt()
{

}

void DEA::initialPermutation(int64_t &cipherBlock64Bits)
{

}

void DEA::permutedChoiceOne(int64_t &cipherKey)
{

}

void DEA::keyOperation(int64_t &cipherKey)
{

}

int64_t DEA::permutedChoiceTwo(int64_t cipherKey)
{

}

void DEA::leftCircularShift(int64_t &cipherKey)
{

}

void DEA::roundOperation(int64_t &cipherBlock, int64_t cipherSubKey)
{

}

int64_t DEA::roundExpansion(int32_t cipherSubBlock)
{

}

int32_t DEA::roundSubstition(int64_t expandedCipherSubBlock)
{

}

void DEA::roundPermutation(int32_t &cipherSubBlock)
{

}

void DEA::bitSwap()
{

}

void DEA::inversePermutation(int64_t &cipherBlock)
{

}

int32_t DEA::exclusiveOr32(int32_t leftCipherSubBlock, int32_t rightCipherSubBlock)
{

}
int64_t DEA::exclusiveOr48(int64_t expandedCipherSubBlock, int64_t cipherSubKey)
{

}
#include "DEA.h"
#include <fstream>
#include <string>
#include <iostream>
DEA::DEA()
{
	this->populatetables();
}

DEA::~DEA()
{

}

uint64_t DEA::encrypt(uint64_t cipherBlock, uint64_t cipherKey)
{
	int i;
	this->generateSubKeys(cipherKey);
	for (i = 0; i < this->NUMBEROFROUNDS; i++)
	{
		cipherBlock = this->roundOperation(cipherBlock, this->subKeyList[i]);
	}
	return cipherBlock;
}

void DEA::decrypt()
{

}

uint64_t DEA::initialPermutation(uint64_t cipherBlock64Bits)
{
	int i;
	uint64_t rearrangedCipherBlock = 0;
	for (i = 0; i < this->CIPHERBLOCKSIZE; i++)
	{
	    //switch bits as table requests. THis builds the cipherblocks bit by bit starting at bit zero
		rearrangedCipherBlock = (rearrangedCipherBlock << 1) | ((cipherBlock64Bits >> (this->CIPHERBLOCKSIZE - this->initialPermutationTable[i])) & 0x01);
	}

	return rearrangedCipherBlock;
}

uint64_t DEA::permutedChoiceOne(uint64_t cipherKey)
{
	int i;
	uint64_t rearrangedKey = 0;
	for (i = 0; i < this->KEYSIZE; i++)
	{
		//add new bit positions to the tempKey 
		rearrangedKey = (rearrangedKey << 1) | ((cipherKey >> (this->CIPHERBLOCKSIZE-this->permutedChoiceOneTable[i])) & 0x01);
	}

	return rearrangedKey;
}


//check keys with java implementation
void DEA::generateSubKeys(uint64_t &cipherKey)
{
	//local variables
	int i;
	uint32_t leftHalf;
	uint32_t rightHalf;
	
	//perform the first permutation with permutationchoiceone table
	uint64_t subKey = this->permutedChoiceOne(cipherKey);

	//split key into two 28 bit components
	leftHalf = ((uint32_t)(subKey >> 28))&this->SPLITKEYSIZEMASK;
	rightHalf = ((uint32_t)subKey)&this->SPLITKEYSIZEMASK;

	//go throught the 16 rounds and generate the subkeys needed for the encryption rounds
	for (i = 0; i < this->NUMBEROFROUNDS; i++)
	{
		leftHalf = this->leftCircularShift(i, leftHalf);
		rightHalf = this->leftCircularShift(i, rightHalf);
		cipherKey = ((uint64_t)leftHalf) << 28 | ((uint64_t)rightHalf);
		this->subKeyList[i] = this->permutedChoiceTwo(cipherKey);
	}
	
}

uint64_t DEA::permutedChoiceTwo(uint64_t cipherKey)
{
	int i;
	uint64_t rearrangedKey = 0;
	for (i = 0; i < this->SUBKEYSIZE; i++)
	{
		//add new bit positions to the tempKey 
		//Algorithm assumes that bit positions are labels as 1 2 3 4 ..ect instead of the msb being leftmost, its rightmost.
		//The bit shifting takes this into account by 64-position to translate msb being leftmost to rightmost. Fucking mathematicians 
		rearrangedKey = (rearrangedKey << 1) | ((cipherKey >> (this->KEYSIZE - this->permutedChoiceTwoTable[i])) & 0x01);
	}

	//clear the top 8 unused bits
	return rearrangedKey&this->SUBKEYSIZEMASK;
}

inline uint32_t DEA::leftCircularShift(int round, uint32_t cipherKey)
{
	return ((cipherKey << this->leftShiftSchedule[round]) & this->SPLITKEYSIZEMASK) | (cipherKey >> (this->SPLITKEYSIZE - this->leftShiftSchedule[round]));
	
}

uint64_t DEA::roundOperation(uint64_t cipherBlock, uint64_t cipherSubKey)
{
	uint32_t leftCipherSubBlock = (uint32_t)(cipherBlock >> 32);
	uint32_t rightCipherSubBlock = (uint32_t)(cipherBlock & 0x00000000FFFFFFFF);

	uint64_t expandedCipherSubBlock = this->roundExpansion(rightCipherSubBlock);
	expandedCipherSubBlock ^= cipherSubKey;
	rightCipherSubBlock = this->roundSubstition(expandedCipherSubBlock);
	rightCipherSubBlock = this->roundPermutation(rightCipherSubBlock);
	rightCipherSubBlock ^= leftCipherSubBlock;
	return ((((uint64_t)leftCipherSubBlock) << 32) & 0xFFFFFFFF00000000) | ((uint64_t)rightCipherSubBlock);
}

uint64_t DEA::roundExpansion(uint32_t cipherSubBlock)
{
	int i;
	uint64_t expandedSubCipherBlock = 0;
	for (i = 0; i < this->SUBKEYSIZE; i++)
	{
		expandedSubCipherBlock = (expandedSubCipherBlock << 1) | ((((uint64_t)cipherSubBlock) >> (this->SUBKEYSIZE - this->expansionPermuationTable[i])) & 0x01);
	}
	return expandedSubCipherBlock;
	
}

uint32_t DEA::roundSubstition(uint64_t expandedCipherSubBlock)
{
	int i;
	int x, y;
	uint64_t cipherMask = 0x000000000000007F;
	uint32_t cipherSubBlock = 0;
	uint8_t sixBitBlock;
	uint8_t xCoord = 0;
	uint8_t yCoord = 0;
	for (i = 0; i < 8; i++)
	{
		//substitution is determined by 8, 6 bit blocks so examine each 6 bit block by using the mask
		//get the six bits and reset six bits as byte instead of long
		sixBitBlock = (uint8_t)(((cipherMask << (i * 6))&expandedCipherSubBlock)>> (i * 6));
		xCoord = (sixBitBlock & 0x20 >> 4) | (sixBitBlock & 0x01);
		yCoord = (sixBitBlock >> 1) & 0x0F;
		cipherSubBlock |= ((uint32_t)this->substitionBoxesArray[i][xCoord][yCoord])<<(i*6);
	}
	return cipherSubBlock;
}

uint32_t DEA::roundPermutation(uint32_t cipherSubBlock)
{
	int i;
	uint32_t rearrangedSubBlock = 0;
	for (i = 0; i < this->CIPHERSUBBLOCKSIZE; i++)
	{
		//add new bit positions to the ciphersubblock 
		rearrangedSubBlock = (rearrangedSubBlock << 1) | ((cipherSubBlock >> (this->CIPHERSUBBLOCKSIZE - this->permutationFunctionTable[i])) & 0x01);
	}

	return rearrangedSubBlock;
}

/*Bit one is the source bit to be moved to bitTwo's location*/
inline uint64_t DEA::switchBit(int bitOneIndex, int bitTwoIndex, uint64_t block)
{

	uint64_t bitOneBlock = (uint64_t)1 << bitOneIndex;
	bitOneBlock = bitOneBlock&block;
	if (bitOneIndex > bitTwoIndex)
	{
		return (bitOneBlock) >> bitOneIndex - bitTwoIndex;
	}
	else
	{
		return (bitOneBlock) << bitTwoIndex - bitOneIndex;
	}
	
}

uint64_t DEA::inversePermutation(uint64_t cipherBlock)
{
	int i;
	uint64_t rearrangedCipherBlock = 0;
	for (i = 0; i < this->CIPHERBLOCKSIZE; i++)
	{
		//switch bits as table requests. THis builds the cipherblocks bit by bit starting at bit zero
		rearrangedCipherBlock = (rearrangedCipherBlock << 1) | ((cipherBlock >> (this->CIPHERBLOCKSIZE - this->inversePermutationTable[i])) & 0x01);
	}

	return rearrangedCipherBlock;
}


void DEA::populatetables()
{
	//helper variables for file io and parsing
	std::ifstream tblFile;
	DEA::table* currentTable;
	DEA::table** subTable;
	tblFile.open("BoxConstants.txt");
	std::string input;
	bool isSubTable = false;
	bool isLSTable = false;

	//allocate memory for the tables
	int i,j;
	substitionBoxesArray = new DEA::table**[8];
	for (i = 0; i < 8; i++)
	{
		substitionBoxesArray[i] = new DEA::table*[4];
		for (j = 0; j < 4; j++)
		{
			substitionBoxesArray[i][j] = new DEA::table[16];
		}
	}
	initialPermutationTable = new DEA::table[64];
	inversePermutationTable = new DEA::table[64];
	expansionPermuationTable = new DEA::table[48];
	permutationFunctionTable = new DEA::table[32];
	permutedChoiceOneTable = new DEA::table[56];
	permutedChoiceTwoTable = new DEA::table[48];
	leftShiftSchedule = new DEA::table[16];
	subKeyList = new uint64_t[16];
	

	//declare these helper arrays to avoid warnings
	subTable = substitionBoxesArray[0];
	currentTable = initialPermutationTable;

	int index = 0;
	
	while (std::getline(tblFile, input))
	{
		
		
		if (input.compare("initialpermutation") == 0)
		{
			currentTable = initialPermutationTable;
			index = 0;
			isSubTable = false;
			isLSTable = false;
		}
		else if (input.compare("inversepermutation") == 0)
		{
			currentTable = inversePermutationTable;
			index = 0;
			isSubTable = false;
			isLSTable = false;
		}
		else if (input.compare("expansionpermutation") == 0)
		{
			currentTable = expansionPermuationTable;
			index = 0;
			isSubTable = false;
			isLSTable = false;
		}
		else if (input.compare("permutationfunction") == 0)
		{
			currentTable = permutationFunctionTable;
			index = 0; 
			isSubTable = false;
			isLSTable = false;
		}
		else if (input.compare("substitution0") == 0)
		{
			subTable = substitionBoxesArray[0];
			index = 0;
			isSubTable = true;
			isLSTable = false;
		}
		else if (input.compare("substitution1") == 0)
		{
			subTable = substitionBoxesArray[1];
			index = 0;
			isSubTable = true;
		}
		else if (input.compare("substitution2") == 0)
		{
			subTable = substitionBoxesArray[2];
			index = 0;
			isSubTable = true;
		}
		else if (input.compare("substitution3") == 0)
		{
			subTable = substitionBoxesArray[3];
			index = 0;
			isSubTable = true;
			isLSTable = false;
		}
		else if (input.compare("substitution4") == 0)
		{
			subTable = substitionBoxesArray[4];
			index = 0;
			isLSTable = false;
			isSubTable = true;
		}
		else if (input.compare("substitution5") == 0)
		{
			subTable = substitionBoxesArray[5];
			index = 0;
			isSubTable = true;
			isLSTable = false;
		}
		else if (input.compare("substitution6") == 0)
		{
			subTable = substitionBoxesArray[6];
			index = 0;
			isSubTable = true;
			isLSTable = false;
		}
		else if (input.compare("substitution7") == 0)
		{
			subTable = substitionBoxesArray[7];
			index = 0;
			isSubTable = true;
			isLSTable = false;
		}
		else if (input.compare("permutedone") == 0)
		{
			currentTable = permutedChoiceOneTable;
			index = 0;
			isSubTable = false;
			isLSTable = false;
		}
		else if (input.compare("permutationtwo") == 0)
		{
			currentTable = permutedChoiceTwoTable;
			index = 0;
			isSubTable = false;
			isLSTable = false;
		}
		else if (input.compare("leftshiftschedule") == 0)
		{
			currentTable = leftShiftSchedule;
			index = 0;
			isSubTable = false;
			isLSTable = true;
		}
		else
		{
			if (!isSubTable && !isLSTable)
			{
				currentTable[index] = (uint8_t)std::stoi(input);
				index++;
			}
			else if (isLSTable && !isSubTable)
			{
				currentTable[index] = (uint8_t)std::stoi(input);
				index++;
			}
			else
			{
				subTable[index/16][index%16] = (uint8_t)std::stoi(input);
				index++;
			}
		}
		
	}

	int k;
	for (i = 0; i < 8; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 16; k++)
			{
				std::cout << (int)this->substitionBoxesArray[i][j][k]<<',';
			}
			std::cout << '\n';
		}
		std::cout << '\n';
		std::cout << '\n';
	}
	return;


}
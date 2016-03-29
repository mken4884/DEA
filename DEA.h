#pragma once

#include <cstdint>

/*NOTE TO SELF
 definitely should look into threading this. 
 Many of these operations could be done in parallel. I will implement it and then
 create a multithreaded version*/

//RANDOM NOTES
/*Keys should be generated first because I think they are reused. Add a container to hold
the keys.*/
class DEA {
private:
	/*VARIABLES*/
	uint64_t *subKeyList;

	/*TYPE DEFS & STRUCTS*/
	typedef uint8_t table;
	
	/*CONSTANTS*/
	//holds the left shift cycle for the cipher key, index corresponds to which round and value is number of left shifts
	table*   initialPermutationTable;
	table*   inversePermutationTable;
	table*   expansionPermuationTable;
	table*   permutationFunctionTable;
	table*   permutedChoiceOneTable;
	table*   permutedChoiceTwoTable;
	table*   leftShiftSchedule;
	table*** substitionBoxesArray;


	const uint8_t   CIPHERBLOCKSIZE = 64;
	const uint8_t   CIPHERSUBBLOCKSIZE = 32;
	const uint8_t   KEYSIZE = 56;
	const uint8_t   SPLITKEYSIZE = 28;
	const uint8_t   SUBKEYSIZE = 48;
	const uint8_t   NUMBEROFROUNDS = 16;

	const uint64_t KEYSIZEMASK = 0x00FFFFFFFFFFFFFFF;
	const uint64_t SUBKEYSIZEMASK = 0x0000FFFFFFFFFFFF;
	const uint32_t SPLITKEYSIZEMASK = 0x0FFFFFFF;


	/*FUNCTIONS*/
	void populatetables();
	inline uint64_t switchBit(int bitOneIndex, int bitTwoIndex, uint64_t block);
public:
	/*FUNCTION DEFS*/
	DEA();
	~DEA();
	void encrypt(char* sourceFile, char* destFile, uint64_t cipherKey);
	void decrypt(char* sourceFile, char* destFile, uint64_t cipherKey);
	void encryptBlock(uint64_t* cipherBlock);
	void decryptBlock(uint64_t* cipherBlock);
	uint64_t initialPermutation(uint64_t cipherBlock);
	uint64_t permutedChoiceOne(uint64_t cipherKey);
	void generateSubKeys(uint64_t &cipherKey);
	uint64_t permutedChoiceTwo(uint64_t cipherKey);
	inline uint32_t leftCircularShift(int round, uint32_t cipherKey);
	uint64_t roundOperation(uint64_t cipherBlock, uint64_t cipherSubKey);
	uint64_t roundExpansion(uint32_t cipherSubBlock);
	uint32_t roundSubstition(uint64_t expandedCipherSubBlock);
	uint32_t roundPermutation(uint32_t cipherSubBlock);
	uint64_t inversePermutation(uint64_t cipherBlock);
	uint32_t exclusiveOr32(uint32_t leftCipherSubBlock, uint32_t rightCipherSubBlock);
	uint64_t exclusiveOr48(uint64_t expandedCipherSubBlock,uint64_t cipherSubKey);

	/*CONSTANTS*/

};
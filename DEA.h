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
	int64_t *subKeyList;

	/*TYPE DEFS & STRUCTS*/
	typedef int8_t table;
	
	/*CONSTANTS*/
	//holds the left shift cycle for the cipher key, index corresponds to which round and value is number of left shifts
	const table*  initialPermutationTable;
	const table*  inversePermutationTable;
	const table*  expansionPermuationTable;
	const table*  permutationFunctionTable;
	const table*  inputKeyTable;
	const table*  permutedChoiceOneTable;
	const table*  permutedChoiceTwoTable;
	const int8_t* leftShiftSchedule;
	const table** substitionBoxesArray;
	const int8_t  CIPHERBLOCKSIZE = 64;
	const int8_t  KEYSIZE = 56;
	const int8_t  SUBKEYSIZE = 48;
	const int8_t  NUMBEROFROUNDS = 16;

public:
	/*FUNCTION DEFS*/
	DEA();
	~DEA();
	void encrypt();
	void decrypt();
	void initialPermutation(int64_t &cipherBlock);
	void permutedChoiceOne(int64_t &cipherKey);
	void keyOperation(int64_t &cipherKey);
	int64_t permutedChoiceTwo(int64_t cipherKey);
	void leftCircularShift(int64_t &cipherKey);
	void roundOperation(int64_t &cipherBlock, int64_t cipherSubKey);
	void roundExpansion();
	void roundSubstition();
	void roundPermutation();
	void bitSwap();
	void inversePermutation();
	void exclusiveOr32();

	/*CONSTANTS*/

};
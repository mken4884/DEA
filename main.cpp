#include "DEA.h"
#include <climits>
#include <iostream>

int main()
{
	DEA deaObject;
	uint64_t cipherKey = 1383827165325090801;
	uint64_t cipherBlock;
	deaObject.encrypt("BoxConstants.txt", "encrypted.txt", 0);
	deaObject.decrypt("encrypted.txt", "decrypted.txt", 0);
	//cipherBlock = deaObject.encryptBlock(0x00000000000000000,cipherKey);
	//cipherBlock = deaObject.decryptBlock(cipherBlock, cipherKey);
	//while (1);
}
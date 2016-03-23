#include "DEA.h"
#include <climits>
#include <iostream>

int main()
{
	DEA deaObject;
	uint64_t cipherKey = 1383827165325090801;
	cipherKey = deaObject.encrypt(0x00000000000000000,cipherKey);
	while (1);
}
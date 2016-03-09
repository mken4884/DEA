#include "DEA.h"
#include <climits>

int main()
{
	DEA deaObject;
	uint64_t cipherKey = 1383827165325090801;
	deaObject.generateSubKeys(cipherKey);
}
#include "include.h"

int main(int argc, char const *argv[])
{

	int count =172;
	int i = 0;

	for (i = 0; i < count; ++i)
	{
		if (isprint((char)(i)))
		{
			printf("%c is a char (%d)\n", (char)(i), i);
		}else{
			printf("%c is not a char (%d)\n", (char)(i), i);
		}
	}

	return 0;
}
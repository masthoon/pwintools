#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>
#include <io.h>

int main(int argc, char **argv)
{
	unsigned int real_size;
	char badbuffer[64];
	for (int i = 0; i < 2; i++)
	{
		_write(1, "Size : ", 7);
		scanf("%u", &real_size);
		_write(1, "Input : ", 8);
		scanf("%s", badbuffer);
		_write(1, badbuffer, real_size);
		_write(1, "Done\n", 5);
	}
	return 0;
}

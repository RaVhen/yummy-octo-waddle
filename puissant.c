#include "include.h"

int main(int argc, char * argv[]){
	/* le code de p800 */
	/* le raven il va coder */
	/* la cle sous la forme XX X5 2A 33 77 51 */

	mot32 test = 0x000000;
	printf("%u\n", test);

	int i = 0;

	for(i = 0; i < 8388607; i++){
		test += 0x000001;	
		printf("%u\n", test);
	}


}
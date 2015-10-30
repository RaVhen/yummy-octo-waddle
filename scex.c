#undef DEBUG
#include "include.h"

#define POLY1 0xEF75L
#define POLY2 0x58C2FL
#define POLY3 0x739583L

#define MASK1 0x1FFFFL
#define MASK2 0x7FFFFL
#define MASK3 0x7FFFFFL

mot32  motpar( mot32 w)
{
  w ^=(w>>16);
  w ^=(w>> 8);
  w ^=(w>> 4);
  w ^=(w>> 2);
  w ^=(w>> 1);
  
  return(w&01L);
}


int is_printable(mot08 in){
  int result = 0;
  if(in == ' ' || (in >= 'a' && in <= 'z'))
    return result;
}

int is_ascii(mot08 in){
  if(isprint((char)(in)) != 0 || (int)(in) == 13 || (int)(in) == 0 || 
     (int)(in) == 10){
    /*if((int)(in) >= 0 && (int)(in) <= 127){*/
    return 0;
  }else{
    return 1;
  }
}

int is_utf8(mot08 in){
  /*if (((char)(in) >= 'A' && (char)(in) <= 'Z') || ((char)(in) >= 'a' && 
    (char)(in) <= 'z') || ((unsigned char)(in) >= 0xC0))*/
  if (((unsigned char)(in) >= 0x00 && (unsigned char)(in) <= 0x7f) || 
      ((unsigned char)(in) >= 0xa0 && (unsigned char)(in) <= 0xff))
    {
      return 0;
    }else{
    return 1;
  }
}
/***********************************************************/
/* Systeme de chiffrement par flot scex. Ce systeme est un */
/* exemple pour etudier l'attaque de Siegenthaler.         */
/* La clef fait 59 bits (8 octets)                         */
/*                                                         */
/* Usage scex d|e infile outfile "clef"                    */
/*                                                         */
/* CBA FILIOL Eric                                         */
/***********************************************************/
int main(int argc, char * argv[])
{
  register mot32 reg1, reg2, reg3, regtmp, reb; 
  mot32 i, j;
  FILE * fin, * fout;
  mot08 outblock, lettre, f[8] = {0,0,0,1,0,1,1,1}, x, var;
  char ffout[80];
  int tmp = 0;
  int err_max = 5;
  int nb_zero = 0;
  int analysed_bits = 0;
  int bits_to_analyse = 50*8;
  

  /***************************************/
  /*     Ouverture des fichiers          */
  /***************************************/
  /*fin = fopen(argv[2],"r");
    fout = fopen(argv[3],"w");*/

  /***************************************/
  /* Mise a la clef des registres        */
  /***************************************/
  /*
    reg1 = (mot08)(argv[4][0]) | ((mot08)(argv[4][1]) << 8) | ((mot08)(argv[4][2])
    << 16);
    reg1 &= MASK1;

    reg2 = (mot08)(argv[4][2]) | ((mot08)(argv[4][3]) << 8) | ((mot08)(argv[4][4])
    << 16);
    reg2 >>= 1;
    reg2 &= MASK2; 

    reg3 = (mot08)(argv[4][4]) | ((mot08)(argv[4][5]) << 8) | ((mot08)(argv[4][6])
    << 16) | ((mot08)(argv[4][7]) << 24);
    reg3 >>= 4;
    reg3 &= MASK3;
  */

#ifdef DEBUG
  reg1 = 0x3130;
  reg2 = 0x21999;
  reg3 = 0x66C6A6;
  printf("Etat initiaux des registres : %lx %lx %lx\n", reg1, reg2, reg3);
#endif


  reg1 = 0x17751;
  reg2 = 0x29519;
  /*reg2 = 0x21519;
    reg2 = 0x49519;
    reg2 = 0x9519;
    reg2 = 0x29519;*/
  reg3 = 0x000000;
  /*reg3 = 0x077600;*/

  printf("Crypto %s - Etat initiaux des registres : %lx %lx %lx\n", 
	 argv[3], (long unsigned int)reg1, (long unsigned int)reg2, 
	 (long unsigned int)reg3);

  int ind = 0;

  
  fin = fopen(argv[2],"r"); 
  /*char buffer[6000];*/
  char * buffer;
  int flen = 0;

  fseek(fin, 0, SEEK_END);
  flen = ftell(fin);
  buffer = (char*)calloc(flen+1, sizeof(char));

  for(ind = 0; ind < 8388607; ind++){
    if (tmp == 0x100000 || tmp == 0x200000 || tmp == 0x300000 ||
	tmp == 0x400000 || tmp == 0x500000 || tmp == 0x600000 || 
	tmp == 0x700000 || tmp == 0x800000 || tmp == 0x900000 || 
	tmp == 0xA00000 || tmp == 0xB00000 || tmp == 0xC00000 || 
	tmp == 0xD00000 || tmp == 0xE00000 || tmp == 0xF00000)    	
      {
    	printf("Reach %lx\n", (long unsigned int)reg3);
      }
    tmp++;
    fseek(fin ,0 ,SEEK_SET );
    /*fseek(fout ,0 ,SEEK_SET );**/

    int flag = 0;
    int n = 0;

    reg1 = 0x17751;
    reg2 = 0x29519;
    /*reg2 = 0x21519;
      reg2 = 0x49519;
      reg2 = 0x9519;
      reg2 = 0x29519;*/
    reg3 += 0x000001;
    regtmp = reg3;

    /*printf("Crypto %s - Etat initiaux des registres : %lx %lx %lx\n", 
      argv[1], (long unsigned int)reg1, (long unsigned int)reg2, 
      (long unsigned int)reg3);*/
    /***************************************/
    /* Generation de la suite chiffante    */
    /***************************************/
    j = 0L;
    int returnScan = 0;
    while(returnScan = fscanf(fin,(argv[1][0] == 'e')?"%c":"%02hhX",&lettre), !feof(fin)){
      j++;
      outblock = 0;
      for(i = 0;i < 8;i++){
        x = f[(reg1 & 1) | ((reg2 & 1) << 1) | ((reg3 & 1) << 2)];
        outblock |= (x << i);
        
        reb = motpar(reg1 & POLY1);
        reg1 >>=1;
        reg1 |= reb?0x10000L:0L;
        /* Autre solution reg1 |= (reb << 16); */
        
        reb = motpar(reg2 & POLY2);
        reg2 >>=1;
        reg2 |= reb?0x40000L:0L;
        /* Autre solution reg2 |= (reb << 18); */

        reb = motpar(reg3 & POLY3);
        reg3 >>=1;
        reg3 |= reb?0x400000L:0L;
        /* Autre solution reg3 |= (reb << 22); */
      }
#ifdef DEBUG
      printf("%lx\n",outblock);
#endif
      if(argv[1][0] == 'e') fprintf(fout,"%02X",lettre^outblock);
      else{
        /*printf("%c\n", lettre^outblock);*/
        /*fprintf(fout,"%c",lettre^outblock);*/

	/*var = lettre^outblock;
	buffer[n] = (int)(lettre^outblock);
	
	for(tmp = 0; tmp < 8; tmp++)
	  {
	    if(var%2==0)
	      nb_zero++;
	    var >>= 1;
	  }
	analysed_bits += 8;

	if(analysed_bits >= bits_to_analyse)
	  {
	    if((double)((double)nb_zero/(double)analysed_bits) < 0.515)
	      {
		printf("Walla jo z");
		flag = 100;
		analysed_bits = 0;
		bits_to_analyse = 0;
		nb_zero = 0;
		break;
	      }
	    else
	      {
		flag = 0;
		printf("Coucou\n");
		flag = 0;
		analysed_bits = 0;
		bits_to_analyse = 0;
		nb_zero = 0;
		break;
	      }
	  }*/
	if (is_utf8(lettre^outblock) == 0)
	  {
	    buffer[n] = (int)(lettre^outblock);
	    n++;
	  }else{
	  flag += 1;
	  if (flag > err_max)
	    {
	      break;
	    }
	    }
      } 
    }

    reg3 = regtmp;

    /* found a correct decrypt */
    if(flag <= err_max){
      snprintf(ffout, sizeof ffout, "%s%s%s%s%lx", argv[3], "_", argv[2], "_", 
	       (long unsigned int)reg3);
      printf("%s\n", ffout);
      fout = fopen(ffout,"w");
      fprintf(fout, "%s", buffer);
      fclose(fout);
      /*break;*/
    }
  }
  printf("%lx\n", (long unsigned int)reg3);
  fclose(fin);
  free(buffer);

#ifdef DEBUG
  printf("Nombre de lettres traitees : %d\n",j);
#endif
}

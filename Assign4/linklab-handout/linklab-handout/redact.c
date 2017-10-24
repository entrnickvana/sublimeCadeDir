#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <elf.h>
#include "decode.h"

/* Given the in-memory ELF header pointer as `ehdr` and a section
   header pointer as `shdr`, returns a pointer to the memory that
   contains the in-memory content of the section */
#define AT_SEC(ehdr, shdr) ((void *)(ehdr) + (shdr)->sh_offset)

static int get_secrecy_level(const char *s); /* foward declaration */

void print_symbols(Elf64_Ehdr* ehdr);
Elf64_Shdr* section_by_name(Elf64_Ehdr* ehdr, char* section_header_name);
Elf64_Shdr* section_by_index(Elf64_Ehdr* ehdr, int index);
void print_dynsym_names(Elf64_Ehdr* ehdr);
Elf64_Sym* sym_by_name(Elf64_Ehdr* ehdr, char* symName, char* symSection);
//Elf64_Sym* sym_by_name(Elf64_Ehdr* ehdr, char* symName);
Elf64_Sym* sym_by_index(Elf64_Ehdr* ehdr, int index, char* nameOfSymSection);
//Elf64_Sym* sym_by_index(Elf64_Ehdr* ehdr, int index);
int map_dynsym_to_shndx(Elf64_Ehdr* ehdr,  int symbolIndex, char* nameOfSymSection);
//int map_dynsym_to_shndx(Elf64_Ehdr* ehdr,  int symbolIndex);
void printSectionHeaderNames(Elf64_Ehdr* ehdr);
unsigned char* getMachineCodeOfSymbol(Elf64_Ehdr* ehdr, int symbol_index, char* nameOfSymSection);

/*************************************************************/

void redact(Elf64_Ehdr *ehdr) {
  /* Your work starts here --- but add helper functions that you call
     from here, instead of trying to put all the work in one
     function. */



   Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, ".dynsym");
      int m, sym_arr_size = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

      unsigned char* tempChar;
      for (m = 0; m < sym_arr_size; m++) 
      {
        printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        M: %d\n", m);

          tempChar = getMachineCodeOfSymbol(ehdr, m, ".dynsym");

          if(tempChar != NULL)
            printf("Your byte from main: %02hhx\n\n", *tempChar);

      }

}


unsigned char* getMachineCodeOfSymbol(Elf64_Ehdr* ehdr, int symbol_index, char* nameOfSymSection)
{

        Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, nameOfSymSection);
//        int m = dynsym_shdr->sh_size / sizeof(Elf64_Sym);
        Elf64_Shdr* shdrs = (void*)ehdr+ehdr->e_shoff;

        unsigned char* code_ptr = 0;

        int j = 0;

        Elf64_Sym* Syms = (void*)ehdr + dynsym_shdr->sh_offset;


        if(ELF64_ST_TYPE(Syms[symbol_index].st_info) == STT_FUNC)
        {
            printf("Is a Function!\n");
                
            j = map_dynsym_to_shndx(ehdr, symbol_index, nameOfSymSection);
            printf("M:\t%d  j:\t%d  \n",symbol_index, j );

            code_ptr = AT_SEC(ehdr, shdrs + j) + ((Syms[symbol_index].st_value)-(shdrs[j].sh_addr));

            printf(".text Byte: %02hhx\n", *code_ptr);

            // Print the first bytes of machine code
            int g;
            for (g = 0; g < 10; ++g)
            {
                printf("%02hhx ", *(code_ptr + g));
            }

            printf("\n");

            return code_ptr;

        }else
        {
            printf(" ######   Not a Function!   #######\n");
            j = map_dynsym_to_shndx(ehdr, symbol_index, nameOfSymSection);
            printf("\nM:\t%d  j:\t%d  \n",symbol_index, j );

            return NULL;

        }


}



int map_dynsym_to_shndx(Elf64_Ehdr* ehdr,  int symbolIndex, char* nameOfSymSection)
{
  Elf64_Sym* sym = sym_by_index(ehdr, symbolIndex, nameOfSymSection);
  int sym_shndx = sym->st_shndx;
  Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
  char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset; 

  //printf("Sym Section Header Index: %d\n", sym_shndx);

  printf("Sym shndx corresponds to section: %s\n", strs + section_by_index(ehdr, sym_shndx)->sh_name); 

  return   sym_shndx; 

}

Elf64_Sym* sym_by_index(Elf64_Ehdr* ehdr, int index, char* nameOfSymSection)
{
      unsigned char* strs;

      Elf64_Sym *syms;

      Elf64_Shdr* dynsym_shdr;

      if(strcmp(nameOfSymSection, ".dynsym") == 0)
      {
        dynsym_shdr = section_by_name(ehdr, ".dynsym");

        syms = AT_SEC(ehdr, dynsym_shdr);
        strs = AT_SEC(ehdr, section_by_name(ehdr, ".dynstr"));

      }
      else
      {
        dynsym_shdr = section_by_name(ehdr, ".symtab");

        syms = AT_SEC(ehdr, dynsym_shdr);
        strs = AT_SEC(ehdr, section_by_name(ehdr, ".strtab"));

      }

      printf("%s\n", strs + syms[index].st_name);
      return &syms[index];
}


Elf64_Sym* sym_by_name(Elf64_Ehdr* ehdr, char* symName, char* symSection)
{

  Elf64_Shdr *dynsym_shdr;
  Elf64_Sym *syms;
  char *strs;

  if(strcmp(symSection, ".dynsym") == 0)
  {
      dynsym_shdr = section_by_name(ehdr, ".dynsym");
      syms = AT_SEC(ehdr, dynsym_shdr);
      strs = AT_SEC(ehdr, section_by_name(ehdr, ".dynstr"));      
  }else
  {
      dynsym_shdr = section_by_name(ehdr, ".symtab");
      syms = AT_SEC(ehdr, dynsym_shdr);
      strs = AT_SEC(ehdr, section_by_name(ehdr, ".strtab"));
  }
        int i, count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

      int sym_index = 0;
      for (i = 0; i < count; i++) 
      {
        if(strcmp(strs + syms[i].st_name, symName) == 0)
        { 
          //printf("%s\n", strs + syms[i].st_name);
          //printf("####\n\n\n");
          sym_index = i;
        } 

      }

      return &syms[sym_index];
}

void print_dynsym_names(Elf64_Ehdr* ehdr)
{
      Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, ".dynsym");
      Elf64_Sym *syms = AT_SEC(ehdr, dynsym_shdr);
      char *strs = AT_SEC(ehdr, section_by_name(ehdr, ".dynstr"));
      int i, count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

      for (i = 0; i < count; i++) 
      {
        printf("%s\n", strs + syms[i].st_name);
      }
}


Elf64_Shdr* section_by_index(Elf64_Ehdr* ehdr, int index)
{
    Elf64_Shdr* shdrs = (void*)ehdr+ehdr->e_shoff;
    Elf64_Shdr* desiredSectionHeader = (shdrs + index);

    return desiredSectionHeader;
}


Elf64_Shdr* section_by_name(Elf64_Ehdr* ehdr, char* section_header_name)
{

    Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;
    Elf64_Shdr* desiredSection = NULL;

    int i;

      /*  Shouldnt' be needed*/
//    int index_of_desired_section = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
      //printf("%s\n", strs + shdrs[i].sh_name);

        if( strcmp(strs + shdrs[i].sh_name, section_header_name) == 0 )
        {
           desiredSection =  &shdrs[i];

                 /*  Shouldnt' be needed*/
  //         index_of_desired_section = i;
 //          printf("%s\n", strs + shdrs[i].sh_name);           
        }
    }
  

        /*  Should not be needed  */    
//      void* result;
//      result = AT_SEC(ehdr, desiredSection);
      /*
      printf("\n\nYour Desired Section is located at:\t%p\nWhich point to:\t\t\t%p\t(ehdr + desiredSection->sh_offset\n  Name: \t\t\t%s\n Index: \t\t\t%d\n AT_SEC:  \t\t\t%p\n", 
                desiredSection,
                (void*)ehdr + (desiredSection->sh_offset),
                strs + shdrs[index_of_desired_section].sh_name,
                index_of_desired_section,
                result
              );
      */
      return desiredSection;

}

void printSectionHeaderNames(Elf64_Ehdr* ehdr)
{

    Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;

    int i;
    for (i = 0; i < ehdr->e_shnum; i++) {
      printf("%s\n", strs + shdrs[i].sh_name);
    }

}


/*************************************************************/

static int get_secrecy_level(const char *s) {
  int level = 0;
  int len = strlen(s);
  while (len && (s[len-1] >= '0') && (s[len-1] <= '9')) {
    level = (level * 10) + (s[len-1] - '0');
    --len;
  }
  return level;
}

static void fail(char *reason, int err_code) {
  fprintf(stderr, "%s (%d)\n", reason, err_code);
  exit(1);
}

static void check_for_shared_object(Elf64_Ehdr *ehdr) {
  if ((ehdr->e_ident[EI_MAG0] != ELFMAG0)
      || (ehdr->e_ident[EI_MAG1] != ELFMAG1)
      || (ehdr->e_ident[EI_MAG2] != ELFMAG2)
      || (ehdr->e_ident[EI_MAG3] != ELFMAG3))
    fail("not an ELF file", 0);

  if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
    fail("not a 64-bit ELF file", 0);
  
  if (ehdr->e_type != ET_DYN)
    fail("not a shared-object file", 0);
}

int main(int argc, char **argv) {
  int fd_in, fd_out;
  size_t len;
  void *p_in, *p_out;
  Elf64_Ehdr *ehdr;

  if (argc != 3)
    fail("expected two file names on the command line", 0);

  /* Open the shared-library input file */
  fd_in = open(argv[1], O_RDONLY);
  if (fd_in == -1)
    fail("could not open input file", errno);

  /* Find out how big the input file is: */
  len = lseek(fd_in, 0, SEEK_END);

  /* Map the input file into memory: */
  p_in = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd_in, 0);
  if (p_in == (void*)-1)
    fail("mmap input failed", errno);

  /* Since the ELF file starts with an ELF header, the in-memory image
     can be cast to a `Elf64_Ehdr *` to inspect it: */
  ehdr = (Elf64_Ehdr *)p_in;

  /* Check that we have the right kind of file: */
  check_for_shared_object(ehdr);

  /* Open the shared-library output file and set its size: */
  fd_out = open(argv[2], O_RDWR | O_CREAT, 0777);
  if (fd_out == -1)
    fail("could not open output file", errno);
  if (ftruncate(fd_out, len))
    fail("could not set output file file", errno);

  /* Map the output file into memory: */
  p_out = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
  if (p_out == (void*)-1)
    fail("mmap output failed", errno);

  /* Copy input file to output file: */
  memcpy(p_out, p_in, len);

  /* Close input */
  if (munmap(p_in, len))
    fail("munmap input failed", errno);    
  if (close(fd_in))
    fail("close input failed", errno);

  ehdr = (Elf64_Ehdr *)p_out;

  redact(ehdr);

  if (munmap(p_out, len))
    fail("munmap input failed", errno);    
  if (close(fd_out))
    fail("close input failed", errno);

  return 0;
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>

/* Given the in-memory ELF header pointer as `ehdr` and a section
   header pointer as `shdr`, returns a pointer to the memory that
   contains the in-memory content of the section */
#define AT_SEC(ehdr, shdr) ((void *)(ehdr) + (shdr)->sh_offset)
//#define ELF64_ST_TYPE(st_info) ((st_info) & 0xf)

static void check_for_shared_object(Elf64_Ehdr *ehdr);
static void fail(char *reason, int err_code);
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



int main(int argc, char **argv) 
{
  int fd;
  size_t len;
  void *p;
  Elf64_Ehdr *ehdr;

  if (argc != 2)
    fail("expected one file on the command line", 0);

  /* Open the shared-library file */
  fd = open(argv[1], O_RDONLY);
  if (fd == -1)
    fail("could not open file", errno);
 
  /* Find out how big the file is: */
  len = lseek(fd, 0, SEEK_END);

  /* Map the whole file into memory: */
  p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (p == (void*)-1)
    fail("mmap failed", errno);

  /* Since the ELF file starts with an ELF header, the in-memory image
     can be cast to a `Elf64_Ehdr *` to inspect it: */
  ehdr = (Elf64_Ehdr *)p;

  /* Check that we have the right kind of file: */
  check_for_shared_object(ehdr);

  /* Your work for parts 1-6 goes here */

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

      //printSectionHeaderNames( ehdr);

  return 0;
}

unsigned char* getMachineCodeOfSymbol(Elf64_Ehdr* ehdr, int symbol_index, char* nameOfSymSection)
{

        Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, nameOfSymSection);
        int m, sym_arr_size = dynsym_shdr->sh_size / sizeof(Elf64_Sym);
        Elf64_Shdr* shdrs = (void*)ehdr+ehdr->e_shoff;

        unsigned char* code_ptr = 0;

        int j = 0;
        int temp  = 0;

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
  unsigned char *strs;

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

      int sym_index;
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
    Elf64_Shdr* desiredSection;

    int i;
    int index_of_desired_section = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
      //printf("%s\n", strs + shdrs[i].sh_name);

        if( strcmp(strs + shdrs[i].sh_name, section_header_name) == 0 )
        {
           desiredSection =  &shdrs[i];
           index_of_desired_section = i;
 //          printf("%s\n", strs + shdrs[i].sh_name);           
        }
    }
      
      void* result;
      result = AT_SEC(ehdr, desiredSection);
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

/* Just do a little bit of error-checking:
   Make sure we're dealing with an ELF file. */
static void check_for_shared_object(Elf64_Ehdr *ehdr) 
{
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

static void fail(char *reason, int err_code) 
{
  fprintf(stderr, "%s (%d)\n", reason, err_code);
  exit(1);
}

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

/* Given the in-memory ELF header pointer as `ehdr` and a section
   header pointer as `shdr`, returns a pointer to the memory that
   contains the in-memory content of the section */
#define AT_SEC(ehdr, shdr) ((void *)(ehdr) + (shdr)->sh_offset)


#define DEBUG 1

#ifdef DEBUG
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) do {} while(0)
#endif

static int get_secrecy_level(const char *s); /* foward declaration */
void printSectionNames(Elf64_Ehdr *ehder);
void printSectionNamesFromArray(Elf64_Ehdr* ehdr, char* sectNamePtrs[]);
void getSectionBaseAddrss(Elf64_Ehdr* ehdr, char* sectNamePtrs[]);
void getSectPtr(Elf64_Ehdr* ehdr, char* nameOfSection, char* names[], Elf64_Shdr* out);
Elf64_Shdr* section_by_name(Elf64_Ehdr* ehdr, char* section_header_name);
void print_dynsym_names(Elf64_Ehdr* ehdr);
void print_sym_names(Elf64_Ehdr* ehdr);

/*************************************************************/

void redact(Elf64_Ehdr *ehdr) {
  /* Your work starts here --- but add helper functions that you call
     from here, instead of trying to put all the work in one
     function. */
  printf("1     ##############################\n");
  print_dynsym_names(ehdr);
  printf("2     #############################################################################\n");
  print_sym_names(ehdr);


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


void print_sym_names(Elf64_Ehdr* ehdr)
{
      Elf64_Shdr *sym_shdr = section_by_name(ehdr, ".symtab");
      Elf64_Sym *syms = AT_SEC(ehdr, sym_shdr);
      char *strs = AT_SEC(ehdr, section_by_name(ehdr, ".strtab"));
      int i, count = sym_shdr->sh_size / sizeof(Elf64_Sym);

      for (i = 0; i < count; i++) 
      {
        printf("%s\n", strs + syms[i].st_name);
      }
}

Elf64_Shdr* section_by_name(Elf64_Ehdr* ehdr, char* section_header_name)
{

    Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;
    Elf64_Shdr* desiredSection;

    int i;
    int index_of_desired_section = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
      printf("%s\n", strs + shdrs[i].sh_name);

        if( strcmp(strs + shdrs[i].sh_name, section_header_name) == 0 )
        {
           desiredSection =  &shdrs[i];
           index_of_desired_section = i;
           printf("%s\n", strs + shdrs[i].sh_name);           
        }
    }
      
      void* result;
      result = AT_SEC(ehdr, desiredSection);
      printf("\n\nYour Desired Section is located at:\t%p\nWhich point to:\t\t\t%p\t(ehdr + desiredSection->sh_offset\n  Name: \t\t\t%s\n Index: \t\t\t%d\n AT_SEC:  \t\t\t%p\n", 
                desiredSection,
                (void*)ehdr + (desiredSection->sh_offset),
                strs + shdrs[index_of_desired_section].sh_name,
                index_of_desired_section,
                result
              );

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


void getSectPtr(Elf64_Ehdr* ehdr, char* nameOfSection, char* names[], Elf64_Shdr* out){

  int i = 0;
  int index = 0;
      DEBUG_PRINT(("________1_________\n"));
  // Get the section index
  for (i = 0; i < ehdr->e_shnum; i++)
      if(strcmp(names[i], nameOfSection) == 0){
              DEBUG_PRINT(("________1_%d_________\n", i));
        index = i;
      }

      DEBUG_PRINT(("________2_________\n"));

      DEBUG_PRINT(("Index is: %d", index));

  // Get the pointer to the section

  Elf64_Shdr* baseOfshdrArr = (void*)ehdr + ehdr->e_shoff;
          DEBUG_PRINT(("________3_________\n"));

          DEBUG_PRINT(("base pointer: %p\n", baseOfshdrArr));

  *out = baseOfshdrArr[index];

        DEBUG_PRINT(("________4_________\n"));

        DEBUG_PRINT(("base pointer + index: %p\n", out));
}


/*
  Section#: 1 .note.gnu.build-id
  Section#: 2 .gnu.hash
  Section#: 3 .dynsymP
  Section#: 4 .dynstr
  Section#: 5 .gnu.version
  Section#: 6 .gnu.version_r
  Section#: 7 .rela.dyn
  Section#: 8 .rela.plt
  Section#: 9 .init
  Section#: 10 .plt
  Section#: 11 .text
  Section#: 12 .fini
  Section#: 13 .eh_frame_hdr
  Section#: 14 .eh_frame
  Section#: 15 .init_array
  Section#: 16 .fini_array
  Section#: 17 .jcr
  Section#: 18 .data.rel.ro
  Section#: 19 .dynamic
  Section#: 20 .got
  Section#: 21 .got.plt
  Section#: 22 .data
  Section#: 23 .bss
  Section#: 24 .comment
  Section#: 25 .shstrtab
  Section#: 26 .symtab
  Section#: 27 .strtab

*/


/*
  Mostly useful for debugging
*/
void printSectionNamesFromArray(Elf64_Ehdr* ehdr, char* sectNamePtrs[]){

    printf("Beginning printing array of names\n");

    int i = 0;
    for (i = 0; i < ehdr->e_shnum; i++){
        printf("Section#: %d %s\n",i, sectNamePtrs[i]);
    }

}




void printSectionNames(Elf64_Ehdr* ehdr){


      Elf64_Shdr* shdrs = (void*)ehdr + ehdr->e_shoff;
      char* strs = (void*)ehdr + shdrs[ehdr->e_shstrndx].sh_offset; 
      printf("%d\n", ehdr->e_shstrndx);

      int i;

      for (i = 0; i < ehdr->e_shnum; i++)
      {
        printf("Iteration: i = %d,  name = %s\n",i, strs + shdrs[i].sh_name);
      }

}

/*
  The second parameter char* sectNamePtrs
*/

void getSectionBaseAddrss(Elf64_Ehdr* ehdr, char* sectNamePtrs[]){


      Elf64_Shdr* shdrs = (void*)ehdr + ehdr->e_shoff;
      char* strs = (void*)ehdr + shdrs[ehdr->e_shstrndx].sh_offset; 

      int k = 0;

      for (k = 0; k < ehdr->e_shnum; k++){
          DEBUG_PRINT(("___%d___\n", k));
          sectNamePtrs[k] = strs + shdrs[k].sh_name;
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

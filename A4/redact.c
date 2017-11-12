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

#define DEBUG 1
#ifdef DEBUG
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif

/* Given the in-memory ELF header pointer as `ehdr` and a section
   header pointer as `shdr`, returns a pointer to the memory that
   contains the in-memory content of the section */


#define AT_SEC(ehdr, shdr) ((void *)(ehdr) + (shdr)->sh_offset)

static int get_secrecy_level(const char *s); /* foward declaration */

// ADDED FUNCTIONS
void p_shdrs(Elf64_Ehdr*  ehdr);
void p_syms(Elf64_Ehdr* ehdr);
Elf64_Shdr *section_by_index(Elf64_Ehdr *ehdr, int idx);
Elf64_Shdr *section_by_name(Elf64_Ehdr *ehdr, char *name);
// ADDED FUNCTIONS

/*************************************************************/

void redact(Elf64_Ehdr *ehdr) 
{
  p_shdr_nms(ehdr); // print shdrs
  p_syms(ehdr);



}

void p_syms(Elf64_Ehdr* ehdr)
{
  DEBUG_PRINT(("------------------------------SYMBOL NAMES------------------------\n"));
    Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, ".dynsym");
    Elf64_Sym *syms = AT_SEC(ehdr, dynsym_shdr);
    char *strs = AT_SEC(ehdr, section_by_name(ehdr, ".dynstr"));
    int i, count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);
    for (i = 0; i < count; i++) 
      printf("%s\n", strs + syms[i].st_name);
  
  
    Elf64_Shdr *sym_shdr = section_by_name(ehdr, ".symtab");
    syms = AT_SEC(ehdr, sym_shdr);
    strs = AT_SEC(ehdr, section_by_name(ehdr, ".strtab"));
    count = sym_shdr->sh_size / sizeof(Elf64_Sym);
    for (i = 0; i < count; i++) 
      printf("%s\n", strs + syms[i].st_name);
  DEBUG_PRINT(("-------------------------------SYMBOL NAMES------------------------\n"));
}


void p_shdrs(Elf64_Ehdr*  ehdr)
{
  DEBUG_PRINT(("------------------------------SECTION HDR NAMES------------------------\n"));
  Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
  char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;
  int i;
  for (i = 0; i < ehdr->e_shnum; i++) {
  printf("index: %d\t\t%s\n",i,  strs + shdrs[i].sh_name);
  }
  DEBUG_PRINT(("------------------------------SECTION HDR NAMES------------------------\n"));
}

Elf64_Shdr *section_by_index(Elf64_Ehdr *ehdr, int idx)
{
  Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
  return &shdrs[idx];
}

Elf64_Shdr *section_by_name(Elf64_Ehdr *ehdr, char *nm)
{
  Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
  char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;
  int i;
  for(i = 0; i < ehdr->e_shnum; i++)
    if(strcmp(strs + shdrs[i].sh_name, nm) == 0)
      return &shdrs[i];
  return NULL;
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

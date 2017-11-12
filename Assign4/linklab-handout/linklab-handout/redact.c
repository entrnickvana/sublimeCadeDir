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
void print_dynsym_names(Elf64_Ehdr* ehdr, char* symTypeName, char* symStrSectionName);
Elf64_Sym* sym_by_name(Elf64_Ehdr* ehdr, char* symName, char* symSection);
//Elf64_Sym* sym_by_name(Elf64_Ehdr* ehdr, char* symName);
Elf64_Sym* sym_by_index(Elf64_Ehdr* ehdr, int index, char* nameOfSymSection);
//Elf64_Sym* sym_by_index(Elf64_Ehdr* ehdr, int index);
int map_dynsym_to_shndx(Elf64_Ehdr* ehdr,  int symbolIndex, char* nameOfSymSection);
//int map_dynsym_to_shndx(Elf64_Ehdr* ehdr,  int symbolIndex);
void printSectionHeaderNames(Elf64_Ehdr* ehdr);
unsigned char* getMachineCodeOfSymbol(Elf64_Ehdr* ehdr, int symbol_index, char* nameOfSymSection);
void printRelaInfo(Elf64_Ehdr* ehdr);
void print_Sym_Rela_info(Elf64_Ehdr* ehdr, char* section);
void print_single_dynsym_name(Elf64_Ehdr* ehdr, int symbol_index);
void print_ins_info(Elf64_Ehdr* ehdr, instruction_t* ins);
void print_prev_ins(code_t** code_ptr, instruction_t prev_ins[]);
void advanceIns(instruction_t** ins, code_t** code_ptr, Elf64_Addr* code_addr, instruction_t prev_ins[]);
void increment_storage(instruction_t prev_ins[]);
void print_ins(code_t* code_ptr, instruction_t* ins);
void print_section_runtime_addr(Elf64_Ehdr* ehdr, Elf64_Addr given_addr);
Elf64_Shdr* section_runtime_base_addr(Elf64_Ehdr* ehdr, Elf64_Addr given_addr);
Elf64_Shdr* section_base_addr(Elf64_Ehdr* ehdr, code_t* given_addr);
void mov_addr_to_reg_func(Elf64_Ehdr* ehdr, instruction_t* ins, code_t* code_ptr, Elf64_Sym* curr_Sym);
char* relaName(Elf64_Ehdr* ehdr, int rela_index);
void maybe_jmp_to_addr_func(Elf64_Ehdr* ehdr, instruction_t* ins_ptr2, instruction_t* ins, code_t* temp_code_ptr,  code_t* code_ptr, Elf64_Sym* curr_Sym, int* symbolM_index);
void other_op_func(Elf64_Ehdr* ehdr, instruction_t* ins, code_t* code_ptr, Elf64_Sym* curr_Sym);
void inspectFunctions(Elf64_Ehdr* ehdr,  instruction_t* ins, instruction_t* ins_ptr2, code_t* code_ptr, code_t* temp_code_ptr, Elf64_Sym* curr_Sym, int* symbolM_index);
char* single_dynsym_name(Elf64_Ehdr* ehdr, int symbol_index);


/*************************************************************/

void redact(Elf64_Ehdr *ehdr) {
  /* Your work starts here --- but add helper functions that you call
     from here, instead of trying to put all the work in one
     function. */

    instruction_t prev_ins[5];

    // Initial information
    printSectionHeaderNames(ehdr);
    print_dynsym_names(ehdr, ".symtab", ".strtab");
    print_dynsym_names(ehdr, ".dynsym", ".dynstr");    

    print_Sym_Rela_info(ehdr, ".rela.dyn");
    print_Sym_Rela_info(ehdr, ".rela.plt");    

    printf("DEBUG 0\n");
    char passCode = 'n';
    char passCodeDecode = 'n';
    int counter = 1;
    int m = -1;
    int recurse = 0;
    int recurse_ptr = &recurse;
    int i = 0;
    int temp_index = 0;
    code_t* temp_code_ptr;
    Elf64_Addr base_run_addr;
    int temp_offset = 0;
    Elf64_Addr jmp_addr;
    Elf64_Shdr* temp_Shdr;
    int override = 0;


    Elf64_Shdr* dynsym_shdr = section_by_name(ehdr, ".dynsym");
    Elf64_Shdr* dynstr_shdr = section_by_name(ehdr, ".dynstr");
    Elf64_Shdr* reladyn_shdr = section_by_name(ehdr, ".rela.dyn");
    Elf64_Shdr* relaplt_shdr = section_by_name(ehdr, ".rela.plt"); 
    Elf64_Shdr* plt_shdr = section_by_name(ehdr, ".plt");
    Elf64_Rela* reladyn_ptr = AT_SEC(ehdr, reladyn_shdr);   
    Elf64_Rela* relaplt_ptr = AT_SEC(ehdr, relaplt_shdr);

    char* dyn_strs = AT_SEC(ehdr, dynstr_shdr);
    Elf64_Sym* syms = AT_SEC(ehdr, dynsym_shdr);
    int sym_arr_size = dynsym_shdr->sh_size / sizeof(Elf64_Sym);
    int reladyn_count = reladyn_shdr->sh_size / sizeof(Elf64_Rela);
    int relaplt_count = relaplt_shdr->sh_size / sizeof(Elf64_Rela);    
    int search_result = 0;
    
    Elf64_Rela* rela_arr;

    code_t* code_ptr;
    instruction_t temp_ins;
    instruction_t temp_ins2;    
    instruction_t* ins_ptr2 = &temp_ins2;    
    instruction_t* ins = &temp_ins;

    Elf64_Sym* curr_Sym;
    Elf64_Rela* curr_rela;
    char c;
    char* c_ptr = &c;


    do
    {

      // Increment Symbol
      m++;
      curr_Sym = sym_by_index(ehdr, m, ".dynsym");
      code_ptr = getMachineCodeOfSymbol(ehdr, m, ".dynsym");
      print_single_dynsym_name(ehdr, m);



      if(ELF64_ST_TYPE(syms[m].st_info) == STT_FUNC)
      {

          printf(": Is a function\n");
    
            print_ins(code_ptr, ins);
            decode(ins, code_ptr, curr_Sym->st_value);
            print_ins_info(ehdr, ins);

            inspectFunctions(ehdr, ins, ins_ptr2, code_ptr, temp_code_ptr, curr_Sym, &m);


      }else
      {
        print_single_dynsym_name(ehdr, m);
        printf(": Is a NOT function\n");
      }

      // decode

       // void decode(instruction_t *ins, code_t *code_ptr, Elf64_Addr code_addr);

      // Increment instruction

    } while(m -1 < sym_arr_size);


}

void inspectFunctions(Elf64_Ehdr* ehdr_,  instruction_t* ins_, instruction_t* ins_ptr2_, code_t* code_ptr_, code_t* temp_code_ptr_, Elf64_Sym* curr_Sym_, int* symbolM_index_)
{

      Elf64_Ehdr* ehdr = ehdr_;
      instruction_t temp_ins;
      instruction_t temp_ins2;
      instruction_t temp_ins3;      
      instruction_t temp_ins4;            
      instruction_t* ins = ins_;
      instruction_t* ins_ptr2 = &temp_ins2;
      instruction_t* ins_ptr3 = &temp_ins3;

      instruction_t* ins_ptr4 = &temp_ins4;

      code_t* code_ptr = code_ptr_;
      code_t* temp_code_ptr;
      Elf64_Sym* curr_Sym = curr_Sym_;
      int* symbolM_index = symbolM_index_;
      code_t* another_code_ptr;

      switch(ins->op)
      {
            case 0: //MOV_ADDR_TO_REG_OP,                       
            // Check address for dynamic symbol
              mov_addr_to_reg_func(ehdr, ins, code_ptr, curr_Sym);
              printf("COMPLETED MOV_ADDR_TO_REG AND INCREMENTED CODE_PTR\n");

            code_ptr = code_ptr + ins->length;

            print_ins(code_ptr, ins); 
            decode(ins, code_ptr, curr_Sym->st_value);
            print_ins_info(ehdr, ins);

            inspectFunctions(ehdr, ins, ins_ptr2, code_ptr, temp_code_ptr, curr_Sym, symbolM_index);
  

            break;                                       
            case 1: //JMP_TO_ADDR_OP,                           
              printf("Entered JMP_TO_ADDR_OP\n");                

              Elf64_Addr jmp_addr;
              Elf64_Shdr* relaplt_shdr = section_by_name(ehdr, ".rela.plt");
              Elf64_Rela* rela_arr = AT_SEC(ehdr, relaplt_shdr);


              int relaplt_count = relaplt_shdr->sh_size / sizeof(Elf64_Rela);
              int match_index = -1;
              int i, sym_index;

              Elf64_Addr given_addr = ins->jmp_to_addr.addr;

              for (i = 0; i < relaplt_count; i++) 
              {

                if(rela_arr[i].r_offset == given_addr)
                {
                  match_index = i;
                  printf("\n\n---------------------------------\nINDEX: %d\tMATCH !!!!!!!!!!!!!!!!\n---------------------------------\n\n", i);
                  sym_index = ELF64_R_SYM(rela_arr[i].r_info);
                  print_single_dynsym_name(ehdr, sym_index);
                  if(get_secrecy_level(relaName(ehdr, i)) > get_secrecy_level(single_dynsym_name(ehdr, *symbolM_index)) )
                  {
                    printf("\n----------------------------------\nILLEGAL ACCESS\n----------------------------------\nrela\n");
                    relaName(ehdr, i);
                    printf("Was accessed by:\n");
                    single_dynsym_name(ehdr, *symbolM_index);

                    replace_with_crash(code_ptr, ins);


                  }
                  match_index = i;
                }
                else
                {
                  printf("index: %dno match\n", i);
                  print_single_dynsym_name(ehdr, sym_index);
                }

                if(i < 0)
                {
                  printf("\n\n\t\t##############  NO MATCHES\n\n");
                  break;
                }




              }

            code_ptr = code_ptr + ins->length;

            print_ins(code_ptr, ins); 
            decode(ins, code_ptr, curr_Sym->st_value);
            print_ins_info(ehdr, ins);



            inspectFunctions(ehdr, ins, ins_ptr2, code_ptr, temp_code_ptr, curr_Sym, symbolM_index);



            break;                                   
            case 2: //MAYBE_JMP_TO_ADDR_OP,        

            another_code_ptr = code_ptr + ins->length;

            maybe_jmp_to_addr_func(ehdr,ins_ptr2, ins, temp_code_ptr,  code_ptr, curr_Sym, symbolM_index);
              //void maybe_jmp_to_addr_func(Elf64_Ehdr* ehdr, instruction_t* temp_ins2, instruction_t* ins, code_t* temp_code_ptr,  code_t* code_ptr, Elf64_Sym* curr_Sym, char* passCodeDecode)
            code_ptr = code_ptr + ins->length;

            print_ins(code_ptr, ins); 
            decode(ins_ptr3, another_code_ptr, curr_Sym->st_value);
            print_ins_info(ehdr, ins);

            inspectFunctions(ehdr, ins_ptr3,ins_ptr4 , another_code_ptr, temp_code_ptr, curr_Sym, symbolM_index);            

            
            break;                                         
            case 3: //RET_OP,                                   
            printf("Entered RET_OP\n--------------------------\n");



            print_ins(code_ptr, ins); 
            decode(ins, code_ptr, curr_Sym->st_value);
            print_ins_info(ehdr, ins);
            

            break;                           
            case 4: //OTHER_OP,                    
            other_op_func(ehdr, ins, code_ptr, curr_Sym);

            code_ptr = code_ptr + ins->length;

            print_ins(code_ptr, ins); 
            decode(ins, code_ptr, curr_Sym->st_value);
            print_ins_info(ehdr, ins);


            inspectFunctions(ehdr, ins, ins_ptr2, code_ptr, temp_code_ptr, curr_Sym, symbolM_index);

            break;                             
      }



}



void maybe_jmp_to_addr_func(Elf64_Ehdr* ehdr, instruction_t* ins_ptr2, instruction_t* ins, code_t* temp_code_ptr,  code_t* code_ptr, Elf64_Sym* curr_Sym, int* symbolM_index)
{
    Elf64_Addr base_run_addr;
    Elf64_Shdr* temp_Shdr;

    printf("Entered MAYBE_JMP_TO_ADDR_OP\n-------------------------------------------------\n\n");


    // extract given address

    printf("Given ADDR\n------------\nPTR: %p\tllu: %llu\t\n", (void*)(ins->maybe_jmp_to_addr.addr), (unsigned long long)(ins->maybe_jmp_to_addr.addr));

    //print_section_runtime_addr(ehdr, ins->maybe_jmp_to_addr.addr);
    // discover which section this runtime address belongs to 
    temp_Shdr = section_runtime_base_addr(ehdr,ins->maybe_jmp_to_addr.addr);
    base_run_addr = temp_Shdr->sh_addr;

    // subtract section base run time address from the given runtime address
    printf("OFFSET OF RUNTIME GIVEN ADDR AND BASE ADDR = \t%llu - %llu  = %llu\n", ins->maybe_jmp_to_addr.addr, base_run_addr, ins->maybe_jmp_to_addr.addr - base_run_addr);
    temp_code_ptr = AT_SEC(ehdr, temp_Shdr) + (ins->maybe_jmp_to_addr.addr - base_run_addr);
    section_base_addr(ehdr, temp_code_ptr);
    // add the base in memory address

    // DECODE JUMPED TO INSTRUCTION
    printf("DECODE THE JUMPED TO INSTRUCTION\n-------------------------------------\n");




    

  


}
void other_op_func(Elf64_Ehdr* ehdr, instruction_t* ins, code_t* code_ptr, Elf64_Sym* curr_Sym)
{

    printf("Entered OTHER_OP\n--------------------\n\n");
    printf("MOVED FROM: \t\t");
    print_ins(code_ptr,ins);
    printf("TO: \t\t");
    code_ptr = code_ptr + ins->length;
    print_ins(code_ptr,ins);

}


void mov_addr_to_reg_func(Elf64_Ehdr* ehdr, instruction_t* ins, code_t* code_ptr, Elf64_Sym* curr_Sym)
{

    printf("Entered MOV_ADDR_TO_REG_OP\n");

    Elf64_Addr jmp_addr;
    Elf64_Shdr* reladyn_shdr = section_by_name(ehdr, ".rela.dyn");
    Elf64_Rela* rela_arr = AT_SEC(ehdr, reladyn_shdr);
    int reladyn_count = reladyn_shdr->sh_size / sizeof(Elf64_Rela);
    int search_result;
    int i;

    
    jmp_addr = ins->mov_addr_to_reg.addr;


    printf("\n\nBEGINNIG COMPARISONS OF ADDRESSES\n---------------------------------------\n");
    search_result = -1;
    for(i = 0; i < reladyn_count; i++)
    {

      printf("\nITER: %d\t***\t%llu  --  %llu\t***\n",i,jmp_addr, rela_arr[i].r_offset);
      printf("r_offset correspoinds to runtime section: \t ");
      print_section_runtime_addr(ehdr,rela_arr[i].r_offset);
      printf("jmp_addr corresponds to runtime section: \t");
      print_section_runtime_addr(ehdr,jmp_addr);
      relaName(ehdr, i);

      if(jmp_addr == rela_arr[i].r_offset)
      {
        printf("SYMBOL MATCH FOUND IN THE RELA DYN %d\n", i);
        print_single_dynsym_name(ehdr, i);
        printf(": Corresponds to the match\n");
        search_result = i;
      }
    }

    if(search_result == -1)
    {
      printf("No match found\n");

      code_ptr = code_ptr + ins->length;
      return;
    }else
    {
        char *strs = AT_SEC(ehdr, section_by_name(ehdr, ".dynstr"));

        int secrecy_caller =  get_secrecy_level(strs + curr_Sym->st_name);

        int secrecy_callee = get_secrecy_level(relaName(ehdr, search_result));

        if(secrecy_callee > secrecy_caller)
        {

          printf("\n--------------------------\n REPLACE WITH CRASH!!!!!!!!!!!!!!!!!!! \n--------------------------\n\n");

          replace_with_crash(code_ptr, ins);
          //replace_with_crash(code_ptr, ins);
        }

        code_ptr = code_ptr + ins->length;
    }

}

//int find_rela_match

void advanceIns(instruction_t** ins, code_t** code_ptr, Elf64_Addr* code_addr, instruction_t prev_ins[])
{
  printf("Advance Ins:\n\tLength: %d\tDifference in pointers: %lu\n",(*ins)->length, ( (*code_ptr) + (*ins)->length ) - (*code_ptr)  );
  printf("Old: \t%p\n",*code_ptr);
  increment_storage(prev_ins);
  *code_ptr = (*code_ptr) + (*ins)->length;
  prev_ins[0] = **ins;
  printf("New: \t%p\n\n",*code_ptr);

}

void print_section_runtime_addr(Elf64_Ehdr* ehdr, Elf64_Addr given_addr)
{
   Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;

    int i;
    for (i = 0; i < ehdr->e_shnum -1; i++) {
      //printf("Section Header Name: %s, Section Offset: %p\n", strs + shdrs[i].sh_name, AT_SEC(ehdr, &shdrs[i]));

      if(given_addr > shdrs[i].sh_addr && given_addr < shdrs[i+1].sh_addr)
      {
         printf("Given ADDR is between : %s, - %s\n", strs + shdrs[i].sh_name,strs + shdrs[i+1].sh_name);

      }


    }
}

Elf64_Shdr* section_runtime_base_addr(Elf64_Ehdr* ehdr, Elf64_Addr given_addr)
{
   Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;

    int i;
    for (i = 0; i < ehdr->e_shnum -1; i++) {
      
      if(given_addr > shdrs[i].sh_addr && given_addr < shdrs[i+1].sh_addr)
      {
         printf("Given RUNTIME ADDR is between RUNTIME ADDR's : %s, - %s\n", strs + shdrs[i].sh_name,strs + shdrs[i+1].sh_name);
         return &shdrs[i];
      }

    }

    printf("Returning NULL!!!\n");
    return NULL;
}

Elf64_Shdr* section_base_addr(Elf64_Ehdr* ehdr, code_t* given_addr)
{
   Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;

    int i;
    for (i = 0; i < ehdr->e_shnum -1; i++) {
      
      if(given_addr > (unsigned char*)AT_SEC(ehdr,&shdrs[i]) && given_addr < (unsigned char*)AT_SEC(ehdr, &shdrs[i+1]))
      {
         printf("Given ADDR is between : %s, - %s\n", strs + shdrs[i].sh_name,strs + shdrs[i+1].sh_name);
         return &shdrs[i];
      }

    }

    printf("Returning NULL!!!\n");
    return NULL;
}


void print_ins(code_t* code_ptr, instruction_t* ins)
{
            // Print the first bytes of machine code
            int length_of_ins = -1;

            if(ins == NULL || ins->length == 0)
            {
              printf("NO ADDR DETECTED:\n");
              length_of_ins = 5;
            }
            else{
              length_of_ins = ins->length;
            }

            int g;
            for (g = 0; g < length_of_ins; ++g)
            {
                printf("%02hhx ", *(code_ptr + g));
            }

            printf("\n--\n");
}

  
void increment_storage(instruction_t prev_ins[])
{
  instruction_t temp = prev_ins[1];
  prev_ins[1] = temp;

  temp = prev_ins[2];
  prev_ins[2] = temp;

  temp = prev_ins[3];
  prev_ins[3] = temp;

  temp = prev_ins[4];
  prev_ins[4] = temp;
}

void print_prev_ins(code_t** code_ptr, instruction_t prev_ins[])
{
  int i = 0;
  int k = 0;
  code_t* temp = *code_ptr;

  printf("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
  for(i = 0; i < 4; i++)
  {
     if(&prev_ins[i] != NULL)
     {
      for (k = 0; k < prev_ins[i].length; k++)
      {
        printf("%x\t", *temp);
        temp++;
      }
      printf("\n");
    }
  }
  printf("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");

}

void print_ins_info(Elf64_Ehdr* ehdr, instruction_t* ins)
{
  printf("\nTHE DECODED INSTRUCTION WAS INTERPRETED AS:\n--------------------------\n");
  switch(ins->op)
  {
    case 0: printf("OP:\tMOV_ADDR_TO_REG_OP\t\tLENGTH: %d\t\tADDR: %llu\n\n", ins->length, ins->mov_addr_to_reg.addr );break;
    case 1: printf("OP:\tJMP_TO_ADDR_OP\t\tLENGTH: %d\t\tADDR: %llu\n\n", ins->length, ins->jmp_to_addr.addr);break;
    case 2: printf("OP:\tMAYBE_JMP_TO_ADDR_OP\t\tLENGTH: %d\t\tADDR: %llu\n\n", ins->length, ins->maybe_jmp_to_addr.addr );break;
    case 3: printf("OP:\tRET_OP\t\tLENGTH: %d\t\tADDR: NA\n\n", ins->length );break;
    case 4: printf("OP:\tOTHER_OP\t\tLENGTH: %d\t\tADDR: NA\n\n", ins->length );break;
  }





}

void print_Sym_Rela_info(Elf64_Ehdr* ehdr, char* section)
{

  printf("######################  RELA INFO  ######################\n\n");

  Elf64_Shdr* rela_dyn_shdr = section_by_name(ehdr, section);
  Elf64_Rela* relas = AT_SEC(ehdr, rela_dyn_shdr);

  Elf64_Shdr* dyn_sym_shdr = section_by_name(ehdr, ".dynsym");
  Elf64_Sym* Syms = AT_SEC(ehdr, dyn_sym_shdr);


  int i, sym_index, count = rela_dyn_shdr->sh_size / sizeof(Elf64_Rela);
  for (i = 0; i < count; i++) 
  {
    sym_index = ELF64_R_SYM(relas[i].r_info);
    printf("%d -> ", sym_index);
    print_single_dynsym_name(ehdr, sym_index);
    printf("\n");
  }

  printf("######################  RELA INFO  ######################\n\n");

}


void printRelaInfo(Elf64_Ehdr* ehdr)
{

  Elf64_Shdr *rela_dyn_shdr = section_by_name(ehdr, ".rela.dyn");
  Elf64_Rela *relas = AT_SEC(ehdr, rela_dyn_shdr);

  int i, count = rela_dyn_shdr->sh_size / sizeof(Elf64_Rela);
  for (i = 0; i < count; i++) {
    printf("%d\n", ELF64_R_SYM(relas[i].r_info));
  }

}

char* relaName(Elf64_Ehdr* ehdr, int rela_index)
{

  Elf64_Shdr *rela_dyn_shdr = section_by_name(ehdr, ".rela.dyn");
  Elf64_Rela *relas = AT_SEC(ehdr, rela_dyn_shdr);

    int count = rela_dyn_shdr->sh_size / sizeof(Elf64_Rela);

    printf("REQUESTED RELA NAME OF INDEX: %d\n", ELF64_R_SYM(relas[rela_index].r_info));
    
    int rela_to_sym_index = ELF64_R_SYM(relas[rela_index].r_info);

    Elf64_Sym* resultSym = sym_by_index(ehdr, rela_index, ".dynsym");

    Elf64_Shdr* dynstr_shdr = section_by_name(ehdr, ".dynstr");
    char* strs = AT_SEC(ehdr, dynstr_shdr);

    return strs + resultSym->st_name;

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
            //printf("Is a Function!\n");
                
            j = map_dynsym_to_shndx(ehdr, symbol_index, nameOfSymSection);
            //printf("M:\t%d  j:\t%d  \n",symbol_index, j );

            code_ptr = AT_SEC(ehdr, shdrs + j) + ((Syms[symbol_index].st_value)-(shdrs[j].sh_addr));

            printf(".text \nByte: %02hhx\n", *code_ptr);

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
            //printf(" ######   Not a Function!   #######\n");
            j = map_dynsym_to_shndx(ehdr, symbol_index, nameOfSymSection);
            //printf("\nM:\t%d  j:\t%d  \n",symbol_index, j );

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

  printf("SHDR INDEX OF SYM: \t%s", strs + section_by_index(ehdr, sym_shndx)->sh_name); 

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

      printf("Name of Symbol: %s\t\tIndex of Symbol: %d\n", strs + syms[index].st_name, index);
      return &syms[index];
}

void printAllSyms()
{
  int i = 0;


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



void print_dynsym_names(Elf64_Ehdr* ehdr, char* symTypeName, char* symStrSectionName)
{

  printf("@@@@@@@@@@@@@@@@@@@@@@@@@  %s SYMBOL INFO  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n", symTypeName);
      Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, symTypeName);
      Elf64_Sym *syms = AT_SEC(ehdr, dynsym_shdr);
      char *strs = AT_SEC(ehdr, section_by_name(ehdr, symStrSectionName));
      int i, count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

      for (i = 0; i < count; i++) 
      {
        printf("%s\n", strs + syms[i].st_name);
      }

  printf("@@@@@@@@@@@@@@@@@@@@@@@@@  SYMBOL INFO  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");      
}


void print_single_dynsym_name(Elf64_Ehdr* ehdr, int symbol_index)
{

      Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, ".dynsym");
      Elf64_Sym *syms = AT_SEC(ehdr, dynsym_shdr);
      char *strs = AT_SEC(ehdr, section_by_name(ehdr, ".dynstr"));
      int count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);


      if(symbol_index < count)
        printf("%s", strs + syms[symbol_index].st_name);
      else
      {


        Elf64_Shdr *dynsym_shdr2 = section_by_name(ehdr, ".symtab");
        Elf64_Sym *syms2 = AT_SEC(ehdr, dynsym_shdr2);
        char *strs2 = AT_SEC(ehdr, section_by_name(ehdr, ".strtab"));
        int count2 = dynsym_shdr2->sh_size / sizeof(Elf64_Sym);
        if(symbol_index < count2)
        {
              printf("%s", strs2 + syms2[symbol_index].st_name);
        }
        else
        printf("Symbol index out of bounds");
      }
}

char* single_dynsym_name(Elf64_Ehdr* ehdr, int symbol_index)
{
      Elf64_Shdr *dynsym_shdr = section_by_name(ehdr, ".dynsym");
      Elf64_Sym *syms = AT_SEC(ehdr, dynsym_shdr);
      char *strs = AT_SEC(ehdr, section_by_name(ehdr, ".dynstr"));
      int count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

      if(symbol_index < count)
        printf("%s", strs + syms[symbol_index].st_name);
      else
        printf("Symbol index out of bounds");

      return strs + syms[symbol_index].st_name;
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

    for (i = 0; i < ehdr->e_shnum; i++) 
    {
      //printf("%s\n", strs + shdrs[i].sh_name);

        if( strcmp(strs + shdrs[i].sh_name, section_header_name) == 0 )
        {
           desiredSection =  &shdrs[i];
        }
    }

    return desiredSection;

}

void printSectionHeaderNames(Elf64_Ehdr* ehdr)
{

    Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    char *strs = (void*)ehdr+shdrs[ehdr->e_shstrndx].sh_offset;

    int i;
    for (i = 0; i < ehdr->e_shnum; i++) {
      printf("Section Header Name: %s, Section Offset: %p\n", strs + shdrs[i].sh_name, AT_SEC(ehdr, &shdrs[i]));
      if(i < ehdr->e_shnum - 1)
      printf("Difference: %li\n", AT_SEC(ehdr, &shdrs[i]) - AT_SEC(ehdr, &shdrs[i + 1]));

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

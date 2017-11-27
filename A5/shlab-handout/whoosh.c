/* This is the main file for the `whoosh` interpreter and the part
   that you modify. */

#include <stdlib.h>
#include <stdio.h>
#include "csapp.h"
#include "ast.h"
#include "fail.h"

//#define DEBUG_1 1

#ifdef DEBUG_1
# define DEBUG_PRINT1(x) printf x
#else
# define DEBUG_PRINT1(x) do {} while (0)
#endif

//#define DEBUG_2
#ifdef DEBUG_2
# define DEBUG_PRINT2(x) fprintf x
#else
# define DEBUG_PRINT2(x) do {} while (0)
#endif

static void run_script(script *scr);
static void run_group(script_group *group);
static void run_command(script_command *command);
static void set_var(script_var *var, int new_value);
static void printArgInfo(script_argument *arg);
static void write_string_to(int fd, char *str);
static char *read_to_string(int fd);
static void read_to_var(int fd, script_var *var);
static void write_var_to(int fd, script_var *var);

/* You probably shouldn't change main at all. */

int main(int argc, char **argv) {
  script *scr;
  
  if ((argc != 1) && (argc != 2)) {
    fprintf(stderr, "usage: %s [<script-file>]\n", argv[0]);
    exit(1);
  }

  scr = parse_script_file((argc > 1) ? argv[1] : NULL);

  run_script(scr);

  return 0;
}

static void run_script(script *scr) {
  int i;
      for(i = 0; i < scr->num_groups; ++i)          //  RUN EACH GROUP
            run_group(&scr->groups[i]);
}

static void printArgInfo(script_argument *arg){
  //if(arg->kind == 0)
//    DEBUG_PRINT1(("Lit: %s\n", strcat(arg->u.literal, str_temp)));
  
//  DEBUG_PRINT1(("Var: name: %s, value: %s\n", strcat(arg->u.var->name, str_temp), strcat(arg->u.var->value, str_temp)));
}


/* REQUIREMENTS
    1) Groups must finish consecutively
    2) Group must start each command simultaneously whether AND/OR
*/
static void run_group(script_group *group) {

  int i, j;
  script_command* tmp_cmd;
  int or = -1;
  int and = -1;
  int status;

  for(i = 0; i < group->num_commands; ++i){
    for(j = 0; j < group->repeats; ++j){   //  CALL REPEATS   
        tmp_cmd = &group->commands[i];
        char* out_str;
        int new_in[2];
        int new_out[2];

          if (tmp_cmd->input_from != NULL || tmp_cmd->output_to != NULL)
          {

              if(tmp_cmd->input_from != NULL){ 
                pipe(new_in); 
                write_var_to(new_in[1], tmp_cmd->input_from);
              }

              if(tmp_cmd->output_to != NULL){
                pipe(new_out); 
              }

              pid_t pid = fork();
              if(pid == 0){
                 if(tmp_cmd->input_from != NULL){ dup2(new_in[1], 1);}
                 if(tmp_cmd->output_to != NULL) { dup2(new_out[0], 0);}
                 if(tmp_cmd->pid_to != NULL) { set_var(tmp_cmd->pid_to,getpid());}                 
                 run_command(&group->commands[i]);
              }

              int status;
              switch(group->mode)
                {
                  case 0: waitpid(pid, &status, 0);  or = 0; break;
                  case 1: waitpid(pid, &status, 0);  or = 0; break;
                  case 2: or = 1; break;
                }



              if(tmp_cmd->output_to != NULL){
              close(new_out[1]);
                if(WEXITSTATUS(status) == 0){
                  out_str = read_to_string(new_out[0]);
                    if(out_str[strlen(out_str) - 1] == '\n') {out_str[strlen(out_str) - 1] = '0';} 
                  read_to_var(new_out[0], tmp_cmd->output_to);
                }
              }

          }else{ 
              pid_t pid = fork(); 
              if(pid == 0){run_command(&group->commands[i]);} 

              if(tmp_cmd->pid_to != NULL) { set_var(tmp_cmd->pid_to, getpid());}                                 
              
              int status;
              switch(group->mode)
                {
                  case 0: waitpid(pid, &status, 0);  or = 0; break;
                  case 1: waitpid(pid, &status, 0); break;
                  case 2: or = 1; break;
                }
          }
    }
  }
  if(or == 1){wait(&status); or = 0;}

}


/* This run_command function is a good start, but note that it runs
   the command as a replacement for the `whoosh` script, instead of
   creating a new process. */
static void run_command(script_command *command){

  int i;
  const char **argv;
  
  argv = malloc(sizeof(char *) * (command->num_arguments + 2));  // dynamic allocation for script string args
  argv[0] = command->program;  // dynamic allocation for script itself

  for (i = 0; i < command->num_arguments; i++) 
  {
    if(command->arguments[i].kind == ARGUMENT_LITERAL)
      argv[i+1] = command->arguments[i].u.literal;
    else
      argv[i+1] = command->arguments[i].u.var->value;

  }

  argv[command->num_arguments + 1] = NULL;

  Execve(argv[0], (char * const *)argv, environ);

  free(argv);
}


static void write_string_to(int fd, char *str) {
  size_t len = strlen(str);
  ssize_t wrote = Write(fd, str, len);
  if (wrote != len)
    app_error("didn't write all expected bytes");
}

static char *read_to_string(int fd) {
  size_t size = 4097, amt = 0;
  char buffer[size];
  ssize_t got;

  while (1) {
    got = Read(fd, buffer + amt, size - amt);
    if (!got) {
      buffer[amt] = 0;
      return strdup(buffer);
    }
    amt += got;
    if (amt > (size - 1))
      app_error("received too much output");
  }
}

/* You'll likely want to use this set_var function for converting a
   numeric value to a string and installing it as a variable's
   value: */
static void set_var(script_var *var, int new_value) {
  char buffer[32];
  free((void*)var->value);
  snprintf(buffer, sizeof(buffer), "%d", new_value);
  var->value = strdup(buffer);
}

/* You'll likely want to use this write_var_to function for writing a
   variable's value to a pipe: */
static void write_var_to(int fd, script_var *var) {
  size_t len = strlen(var->value);
  ssize_t wrote = Write(fd, var->value, len);
  wrote += Write(fd, "\n", 1);
  if (wrote != len + 1)
    app_error("didn't write all expected bytes");
}

/* You'll likely want to use this write_var_to function for reading a
   pipe's content into a variable: */
static void read_to_var(int fd, script_var *var) {
  size_t size = 4097, amt = 0;
  char buffer[size];
  ssize_t got;

  while (1) {
    got = Read(fd, buffer + amt, size - amt);
    if (!got) {
      if (amt && (buffer[amt-1] == '\n'))
        amt--;
      buffer[amt] = 0;
      free((void*)var->value);
      var->value = strdup(buffer);
      return;
    }
    amt += got;
    if (amt > (size - 1))
      app_error("received too much output");
  }
}

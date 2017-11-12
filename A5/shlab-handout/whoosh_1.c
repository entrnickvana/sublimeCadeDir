/* This is the main file for the `whoosh` interpreter and the part
   that you modify. */

#include <stdlib.h>
#include <stdio.h>
#include "csapp.h"
#include "ast.h"
#include "fail.h"

#define DEBUG_1 1

#ifdef DEBUG_1
# define DEBUG_PRINT1(x) printf x
#else
# define DEBUG_PRINT1(x) do {} while (0)
#endif

#define DEBUG_2 1
#ifdef DEBUG_2
# define DEBUG_PRINT2(x) printf x
#else
# define DEBUG_PRINT2(x) do {} while (0)
#endif

static void run_script(script *scr);
static void run_group(script_group *group);
static void run_command(script_command *command);
static void set_var(script_var *var, int new_value);
static void print_group_info(script_group *group);

/* You probably shouldn't change main at all. */

int main(int argc, char **argv) {
  script *scr;
  int z = 666;
  char* billy = "Billy";
 
  DEBUG_PRINT1(("\t$$$ ENTERED MAIN $$$\n")); 

  if ((argc != 1) && (argc != 2)) {
    fprintf(stderr, "usage: %s [<script-file>]\n", argv[0]);
    exit(1);
  }

  scr = parse_script_file((argc > 1) ? argv[1] : NULL);

  run_script(scr);

  return 0;
}

static void run_script(script *scr) {
  if (scr->num_groups == 1) {
      DEBUG_PRINT1(("^^^ ENTERED run_sript GROUPS: 1  ^^^\n")); 
      run_group(&scr->groups[0]);
  }
  else
  {
      DEBUG_PRINT1(("*** ENTERED run_sript GROUPS: > 1 ***\n")); 
    int i;
    for (i = 0; i < scr->num_groups; i++)  
    {
        int pid = fork();
        if(pid == 0)
        {
          run_group(&scr->groups[i]);
          exit(0);
        }
        else
        {
          int status_of_child;
          Waitpid(pid, &status_of_child, 0);
        }
    }

    exit(0);

  }
}

static void run_group(script_group *group) {

  DEBUG_PRINT1(("\t*** ENTERED run_sript GROUPS: > 1 ***\n")); 
  print_group_info(group);

  int i;
  if (group->num_commands == 1) 
  {
    for(i = 0; i < group->repeats; i++)  
    {
      run_command(&group->commands[i]);
      DEBUG_PRINT1(("Repeat: %d", i));
    }

    exit(0);
  }
  else 
  {

  }
}

static void print_group_info(script_group *group)
{
    if(group->mode == 0)
      {
        DEBUG_PRINT2(("MODE: GROUP_SINGLE\t\t\n"));
      }
    else if(group->mode == 1)
      {
        DEBUG_PRINT2(("MODE: GROUP_AND\t\t\n"));
      } 
    else
      {
        DEBUG_PRINT2(("MODE: GROUP_OR\t\t\n"));
      }

    DEBUG_PRINT2(("REP: %d\t\n", group->repeats));

    DEBUG_PRINT2(("#COM: %d\t\n", group->num_commands));
}



/* This run_command function is a good start, but note that it runs
   the command as a replacement for the `whoosh` script, instead of
   creating a new process. */

static void run_command(script_command *command) {
  const char **argv;
  int i;

  if (command->pid_to != NULL)
    fail("setting process ID variable not supported");
  if (command->input_from != NULL)
    fail("input from variable not supported");
  if (command->output_to != NULL)
    fail("output to variable not supported");

  argv = malloc(sizeof(char *) * (command->num_arguments + 2));
  argv[0] = command->program;
  
  for (i = 0; i < command->num_arguments; i++) {
    if (command->arguments[i].kind == ARGUMENT_LITERAL)
      argv[i+1] = command->arguments[i].u.literal;
    else
      argv[i+1] = command->arguments[i].u.var->value;
  }
  
  argv[command->num_arguments + 1] = NULL;

  Execve(argv[0], (char * const *)argv, environ);

  free(argv);
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

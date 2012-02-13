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
 
 missingproclion.h
 
 */

#define MACH_KERNEL_PRIVATE
#define __APPLE_API_UNSTABLE
#define SYSCTL_DEF_ENABLED
#define PROC_DEF_ENABLED
#define MACH_KERNEL_PRIVATE

// we need this to complete the proc structure
// osfmk/i386/locks.h
// changed in LION

struct lck_mtx_t {
	union {
		struct {
			volatile uintptr_t		lck_mtxd_owner;
			union {
				struct {
					volatile uint32_t
				lck_mtxd_waiters:16,
				lck_mtxd_pri:8,
				lck_mtxd_ilocked:1,
				lck_mtxd_mlocked:1,
				lck_mtxd_promoted:1,
				lck_mtxd_spin:1,
				lck_mtxd_is_ext:1,
				lck_mtxd_pad3:3;
				};
				uint32_t	lck_mtxd_state;
			};
#if	defined(__x86_64__)
			/* Pad field used as a canary, initialized to ~0 */
			uint32_t			lck_mtxd_pad32;
#endif			
		} lck_mtxd;
		struct {
			struct _lck_mtx_ext_		*lck_mtxi_ptr;
			uint32_t			lck_mtxi_tag;
#if	defined(__x86_64__)				
			uint32_t			lck_mtxi_pad32;
#endif			
		} lck_mtxi;
	} lck_mtx_sw;
};		



// osfmk/i386/locks.h

struct lck_spin_t {
	volatile uintptr_t	interlock;
#if	MACH_LDEBUG
	unsigned long   lck_spin_pad[9];	/* XXX - usimple_lock_data_t */
#endif
};


// ripped from xnu/bsd/sys/proc_internal.h
// Needed so we can access the proc structure passed to the syscall
// I had to comment some fields because other kernel includes would be needed
// This should be valid since we are not doing any copies of this structure (just having it's definition to avoid dereference pointer to incomplete types)
// else things might go wrong (big kabooommm)
// FOR LION
struct	proc {
	LIST_ENTRY(proc) p_list;		/* List of all processes. */
	
	pid_t		p_pid;			/* Process identifier. (static)*/
	void * 		task;			/* corresponding task (static)*/
	struct	proc *	p_pptr;		 	/* Pointer to parent process.(LL) */
	pid_t		p_ppid;			/* process's parent pid number */
	pid_t		p_pgrpid;		/* process group id of the process (LL)*/
	uid_t		p_uid;
	gid_t		p_gid;
	uid_t		p_ruid;
	gid_t		p_rgid;
	uid_t		p_svuid;
	gid_t		p_svgid;
	uint64_t	p_uniqueid;		/* process uniqe ID */
	
	struct lck_mtx_t 	p_mlock;		/* mutex lock for proc */
	
	char		p_stat;			/* S* process status. (PL)*/
	char		p_shutdownstate;
	char		p_kdebug;		/* P_KDEBUG eq (CC)*/ 
	char		p_btrace;		/* P_BTRACE eq (CC)*/
	
	LIST_ENTRY(proc) p_pglist;		/* List of processes in pgrp.(PGL) */
	LIST_ENTRY(proc) p_sibling;		/* List of sibling processes. (LL)*/
	LIST_HEAD(, proc) p_children;		/* Pointer to list of children. (LL)*/
	TAILQ_HEAD( , uthread) p_uthlist; 	/* List of uthreads  (PL) */
	
	LIST_ENTRY(proc) p_hash;		/* Hash chain. (LL)*/
	TAILQ_HEAD( ,eventqelt) p_evlist;	/* (PL) */
	
	struct lck_mtx_t	p_fdmlock;		/* proc lock to protect fdesc */
	
	/* substructures: */
	kauth_cred_t	p_ucred;		/* Process owner's identity. (PL) */
	struct	filedesc *p_fd;			/* Ptr to open files structure. (PFDL) */
	struct	pstats *p_stats;		/* Accounting/statistics (PL). */
	struct	plimit *p_limit;		/* Process limits.(PL) */
	
	struct	sigacts *p_sigacts;		/* Signal actions, state (PL) */
	int		p_siglist;		/* signals captured back from threads */
	struct lck_spin_t	p_slock;		/* spin lock for itimer/profil protection */
	
#define	p_rlimit	p_limit->pl_rlimit
	
	struct	plimit *p_olimit;		/* old process limits  - not inherited by child  (PL) */
	unsigned int	p_flag;			/* P_* flags. (atomic bit ops) */
	unsigned int	p_lflag;		/* local flags  (PL) */
	unsigned int	p_listflag;		/* list flags (LL) */
	unsigned int	p_ladvflag;		/* local adv flags (atomic) */
	int		p_refcount;		/* number of outstanding users(LL) */
	int		p_childrencnt;		/* children holding ref on parent (LL) */
	int		p_parentref;		/* children lookup ref on parent (LL) */
	
	pid_t		p_oppid;	 	/* Save parent pid during ptrace. XXX */
	u_int		p_xstat;		/* Exit status for wait; also stop signal. */
	
#ifdef _PROC_HAS_SCHEDINFO_
	/* may need cleanup, not used */
	u_int		p_estcpu;	 	/* Time averaged value of p_cpticks.(used by aio and proc_comapre) */
	fixpt_t		p_pctcpu;	 	/* %cpu for this process during p_swtime (used by aio)*/
	u_int		p_slptime;		/* used by proc_compare */
#endif /* _PROC_HAS_SCHEDINFO_ */
	
	struct	itimerval p_realtimer;		/* Alarm timer. (PSL) */
	struct	timeval p_rtime;		/* Real time.(PSL)  */
	struct	itimerval p_vtimer_user;	/* Virtual timers.(PSL)  */
	struct	itimerval p_vtimer_prof;	/* (PSL) */
	
	struct	timeval	p_rlim_cpu;		/* Remaining rlim cpu value.(PSL) */
	int		p_debugger;		/*  NU 1: can exec set-bit programs if suser */
	boolean_t	sigwait;	/* indication to suspend (PL) */
	void	*sigwait_thread;	/* 'thread' holding sigwait(PL)  */
	void	*exit_thread;		/* Which thread is exiting(PL)  */
	int	p_vforkcnt;		/* number of outstanding vforks(PL)  */
	void *  p_vforkact;     	/* activation running this vfork proc)(static)  */
	int	p_fpdrainwait;		/* (PFDL) */
	pid_t	p_contproc;	/* last PID to send us a SIGCONT (PL) */
	
	/* Following fields are info from SIGCHLD (PL) */
	pid_t	si_pid;			/* (PL) */
	u_int   si_status;		/* (PL) */
	u_int	si_code;		/* (PL) */
	uid_t	si_uid;			/* (PL) */
	
	void * vm_shm;			/* (SYSV SHM Lock) for sysV shared memory */
	
#if CONFIG_DTRACE
	user_addr_t			p_dtrace_argv;			/* (write once, read only after that) */
	user_addr_t			p_dtrace_envp;			/* (write once, read only after that) */
	lck_mtx_t			p_dtrace_sprlock;		/* sun proc lock emulation */
	int				p_dtrace_probes;		/* (PL) are there probes for this proc? */
	u_int				p_dtrace_count;			/* (sprlock) number of DTrace tracepoints */
	uint8_t                         p_dtrace_stop;                  /* indicates a DTrace-desired stop */
	struct dtrace_ptss_page*	p_dtrace_ptss_pages;		/* (sprlock) list of user ptss pages */
	struct dtrace_ptss_page_entry*	p_dtrace_ptss_free_list;	/* (atomic) list of individual ptss entries */
	struct dtrace_helpers*		p_dtrace_helpers;		/* (dtrace_lock) DTrace per-proc private */
	struct dof_ioctl_data*		p_dtrace_lazy_dofs;		/* (sprlock) unloaded dof_helper_t's */
#endif /* CONFIG_DTRACE */
	
	/* XXXXXXXXXXXXX BCOPY'ed on fork XXXXXXXXXXXXXXXX */
	/* The following fields are all copied upon creation in fork. */
#define	p_startcopy	p_argslen
	
	u_int	p_argslen;	 /* Length of process arguments. */
	int  	p_argc;			/* saved argc for sysctl_procargs() */
	user_addr_t user_stack;		/* where user stack was allocated */
	struct	vnode *p_textvp;	/* Vnode of executable. */
	off_t	p_textoff;		/* offset in executable vnode */
	
	sigset_t p_sigmask;		/* DEPRECATED */
	sigset_t p_sigignore;	/* Signals being ignored. (PL) */
	sigset_t p_sigcatch;	/* Signals being caught by user.(PL)  */
	
	u_char	p_priority;	/* (NU) Process priority. */
	u_char	p_resv0;	/* (NU) User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value.(PL) */
	u_char	p_resv1;	/* (NU) User-priority based on p_cpu and p_nice. */
	
#if CONFIG_MACF
	int	p_mac_enforce;			/* MAC policy enforcement control */
#endif
	
	char	p_comm[MAXCOMLEN+1];
	char	p_name[(2*MAXCOMLEN)+1];	/* PL */
	
	struct 	pgrp *p_pgrp;	/* Pointer to process group. (LL) */
#if CONFIG_EMBEDDED
	int		p_iopol_disk;	/* disk I/O policy (PL) */
#endif /* CONFIG_EMBEDDED */
	uint32_t	p_csflags;	/* flags for codesign (PL) */
	uint32_t	p_pcaction;	/* action  for process control on starvation */
	uint8_t p_uuid[16];		/* from LC_UUID load command */
	
	/* End area that is copied on creation. */
	/* XXXXXXXXXXXXX End of BCOPY'ed on fork (AIOLOCK)XXXXXXXXXXXXXXXX */
#define	p_endcopy	p_aio_total_count
	int		p_aio_total_count;		/* all allocated AIO requests for this proc */
	int		p_aio_active_count;		/* all unfinished AIO requests for this proc */
	TAILQ_HEAD( , aio_workq_entry ) p_aio_activeq; 	/* active async IO requests */
	TAILQ_HEAD( , aio_workq_entry ) p_aio_doneq;	/* completed async IO requests */
	
	//	struct klist p_klist;  /* knote list (PL ?)*/
	
	struct	rusage *p_ru;	/* Exit information. (PL) */
	int		p_sigwaitcnt;
	thread_t 	p_signalholder;
	thread_t 	p_transholder;
	
	/* DEPRECATE following field  */
	u_short	p_acflag;	/* Accounting flags. */
	
	struct lctx *p_lctx;		/* Pointer to login context. */
	LIST_ENTRY(proc) p_lclist;	/* List of processes in lctx. */
	user_addr_t 	p_threadstart;		/* pthread start fn */
	user_addr_t 	p_wqthread;		/* pthread workqueue fn */
	int 	p_pthsize;			/* pthread size */
	user_addr_t	p_targconc;		/* target concurrency ptr */
	void * 	p_wqptr;			/* workq ptr */
	int 	p_wqsize;			/* allocated size */
	boolean_t       p_wqiniting;            /* semaphore to serialze wq_open */
	//	lck_spin_t	p_wqlock;		/* lock to protect work queue */
	struct  timeval p_start;        	/* starting time */
	void *	p_rcall;
	int		p_ractive;
	int	p_idversion;		/* version of process identity */
	void *	p_pthhash;			/* pthread waitqueue hash */
#if DIAGNOSTIC
	unsigned int p_fdlock_pc[4];
	unsigned int p_fdunlock_pc[4];
#if SIGNAL_DEBUG
	unsigned int lockpc[8];
	unsigned int unlockpc[8];
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */
	uint64_t	p_dispatchqueue_offset;
};


// bsd/sys/proc.h
#define	P_TRACED	0x00000800
#define P_NOCLDSTOP     0x00000008      /* No SIGCHLD when children stop */
#define	P_LP64		0x00000004	/* Process is LP64 */

// bsd/sys/sysctl.h
struct _pcred {
	char	pc_lock[72];		/* opaque content */
	struct	ucred *pc_ucred;	/* Current credentials. */
	uid_t	p_ruid;			/* Real user id. */
	uid_t	p_svuid;		/* Saved effective user id. */
	gid_t	p_rgid;			/* Real group id. */
	gid_t	p_svgid;		/* Saved effective group id. */
	int	p_refcnt;		/* Number of references. */
};

// bsd/sys/sysctl.h
struct _ucred {
	int32_t	cr_ref;			/* reference count */
	uid_t	cr_uid;			/* effective user id */
	short	cr_ngroups;		/* number of groups */
	gid_t	cr_groups[NGROUPS];	/* groups */
};

/* Exported fields for kern sysctls */
// bsd/sys/proc_internal.h
struct extern_proc {
	union {
		struct {
			struct	proc *__p_forw;	/* Doubly-linked run/sleep queue. */
			struct	proc *__p_back;
		} p_st1;
		struct timeval __p_starttime; 	/* process start time */
	} p_un;
#define p_forw p_un.p_st1.__p_forw
#define p_back p_un.p_st1.__p_back
#define p_starttime p_un.__p_starttime
	struct	vmspace *p_vmspace;	/* Address space. */
	// bsd/sys/signalvar.h
	struct	sigacts *p_sigacts;	/* Signal actions, state (PROC ONLY). */
	int	p_flag;			/* P_* flags. */
	char	p_stat;			/* S* process status. */
	pid_t	p_pid;			/* Process identifier. */
	pid_t	p_oppid;	 /* Save parent pid during ptrace. XXX */
	int	p_dupfd;	 /* Sideways return value from fdopen. XXX */
	/* Mach related  */
	caddr_t user_stack;	/* where user stack was allocated */
	void	*exit_thread;	/* XXX Which thread is exiting? */
	int		p_debugger;		/* allow to debug */
	boolean_t	sigwait;	/* indication to suspend */
	/* scheduling */
	u_int	p_estcpu;	 /* Time averaged value of p_cpticks. */
	int	p_cpticks;	 /* Ticks of cpu time. */
	fixpt_t	p_pctcpu;	 /* %cpu for this process during p_swtime */
	void	*p_wchan;	 /* Sleep address. */
	char	*p_wmesg;	 /* Reason for sleep. */
	u_int	p_swtime;	 /* Time swapped in or out. */
	u_int	p_slptime;	 /* Time since last blocked. */
	struct	itimerval p_realtimer;	/* Alarm timer. */
	struct	timeval p_rtime;	/* Real time. */
	u_quad_t p_uticks;		/* Statclock hits in user mode. */
	u_quad_t p_sticks;		/* Statclock hits in system mode. */
	u_quad_t p_iticks;		/* Statclock hits processing intr. */
	int	p_traceflag;		/* Kernel trace points. */
	struct	vnode *p_tracep;	/* Trace to vnode. */
	int	p_siglist;		/* DEPRECATED. */
	struct	vnode *p_textvp;	/* Vnode of executable. */
	int	p_holdcnt;		/* If non-zero, don't swap. */
	sigset_t p_sigmask;	/* DEPRECATED. */
	sigset_t p_sigignore;	/* Signals being ignored. */
	sigset_t p_sigcatch;	/* Signals being caught by user. */
	u_char	p_priority;	/* Process priority. */
	u_char	p_usrpri;	/* User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value. */
	char	p_comm[MAXCOMLEN+1];
	struct 	pgrp *p_pgrp;	/* Pointer to process group. */
	struct	user *p_addr;	/* Kernel virtual addr of u-area (PROC ONLY). */
	u_short	p_xstat;	/* Exit status for wait; also stop signal. */
	u_short	p_acflag;	/* Accounting flags. */
	struct	rusage *p_ru;	/* Exit information. XXX */
};


// bsd/sys/sysctl.h
struct kinfo_proc {
	struct  extern_proc kp_proc;                    /* proc structure */
	struct  eproc {
		struct  proc *e_paddr;          /* address of proc */
		struct  session *e_sess;        /* session pointer */
		struct  _pcred e_pcred;         /* process credentials */
		struct  _ucred e_ucred;         /* current credentials */
		struct   vmspace e_vm;          /* address space */
		pid_t   e_ppid;                 /* parent process id */
		pid_t   e_pgid;                 /* process group id */
		short   e_jobc;                 /* job control counter */
		dev_t   e_tdev;                 /* controlling tty dev */
		pid_t   e_tpgid;                /* tty process group id */
		struct  session *e_tsess;       /* tty session pointer */
#define WMESGLEN        7
		char    e_wmesg[WMESGLEN+1];    /* wchan message */
		segsz_t e_xsize;                /* text size */
		short   e_xrssize;              /* text rss */
		short   e_xccount;              /* text references */
		short   e_xswrss;
		int32_t e_flag;
#define EPROC_CTTY      0x01    /* controlling tty vnode active */
#define EPROC_SLEADER   0x02    /* session leader */
#define COMAPT_MAXLOGNAME       12
		char    e_login[COMAPT_MAXLOGNAME];     /* short setlogin() name */
#if CONFIG_LCTX
		pid_t   e_lcid;
		int32_t e_spare[3];
#else
		int32_t e_spare[4];
#endif
	} kp_eproc;
};


struct machine_info {
	integer_t       major_version;          /* kernel major version id */
	integer_t       minor_version;          /* kernel minor version id */
	integer_t       max_cpus;                       /* max number of CPUs possible */
	uint32_t        memory_size;            /* size of memory in bytes, capped at 2 GB */
	uint64_t        max_mem;                        /* actual size of physical memory */
	uint32_t        physical_cpu;           /* number of physical CPUs now available */
	integer_t       physical_cpu_max;       /* max number of physical CPUs possible */
	uint32_t        logical_cpu;            /* number of logical cpu now available */
	integer_t       logical_cpu_max;        /* max number of physical CPUs possible */
};
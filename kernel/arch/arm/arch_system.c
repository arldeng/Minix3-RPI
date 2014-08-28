/* system dependent functions for use inside the whole kernel. */

#include "kernel/kernel.h"

#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <minix/cpufeature.h>
#include <assert.h>
#include <signal.h>
#include <machine/vm.h>

#include <minix/u64.h>

#include "archconst.h"
#include "arch_proto.h"
#include "serial.h"
#include "kernel/proc.h"
#include "kernel/debug.h"
#include "bcm2781_ccnt.h"

#include "glo.h"

void * k_stacks;

static void ser_init(void);

void fpu_init(void)
{
}

void save_local_fpu(struct proc *pr, int retain)
{
}

void save_fpu(struct proc *pr)
{
}

void arch_proc_reset(struct proc *pr)
{
	assert(pr->p_nr < NR_PROCS);

	/* Clear process state. */
        memset(&pr->p_reg, 0, sizeof(pr->p_reg));
        if(iskerneln(pr->p_nr))
        	pr->p_reg.psr = INIT_TASK_PSR;
        else
        	pr->p_seg.psr = INIT_PSR;

	/* set full context and make sure it gets restored */
	arch_proc_setcontext(pr, &reg, 0, KTS_FULLCONTEXT);
}

void arch_set_secondary_ipc_return(struct proc *p, u32_t val)
{
	p->p_reg.r1 = val;
}

void cpu_identify(void)
{
	u32_t midr;
    unsigned cpu = cpuid;
    
    asm volatile("mrc p15, 0, %[midr], c0, c0, 0 @ read MIDR\n\t" : [midr] "=r" (midr));
    
    cpu_info[cpu].implementer = midr >>24;
    cpu_info[cpu].variant = (midr >> 20) & 0xF;
    cpu_info[cpu].arch = (midr >> 16) & 0xF;
    cpu_info[cpu].part = (midr >> 4) & 0xFFF;
    cpu_info[cpu].revision = midr & 0xF;
    cpu_info[cpu].freq = 770; /* hardcoded frequency */
}

void arch_init(void)
{
	k_stacks = (void*) &k_stacks_start;
	assert(!((vir_bytes) k_stacks % K_STACK_SIZE));
}

/*===========================================================================*
 *				do_ser_debug				     * 
 *===========================================================================*/
void do_ser_debug()
{
}

static void ser_dump_queue_cpu(unsigned cpu)
{
	int q;
	struct proc ** rdy_head;
	
	rdy_head = get_cpu_var(cpu, run_q_head);

	for(q = 0; q < NR_SCHED_QUEUES; q++) {
		struct proc *p;
		if(rdy_head[q])	 {
			printf("%2d: ", q);
			for(p = rdy_head[q]; p; p = p->p_nextready) {
				printf("%s / %d  ", p->p_name, p->p_endpoint);
			}
			printf("\n");
		}
	}
}

static void ser_dump_queues(void)
{
	ser_dump_queue_cpu(0);
}

static void ser_debug(const int c)
{
	serial_debug_active = 1;

	switch(c)
	{
	case 'Q':
		minix_shutdown(NULL);
		NOT_REACHABLE;
	case '1':
		ser_dump_proc();
		break;
	case '2':
		ser_dump_queues();
		break;
	case '5':
		ser_dump_vfs();
		break;
#if DEBUG_TRACE
#define TOGGLECASE(ch, flag)				\
	case ch: {					\
		if(verboseflags & flag)	{		\
			verboseflags &= ~flag;		\
			printf("%s disabled\n", #flag);	\
		} else {				\
			verboseflags |= flag;		\
			printf("%s enabled\n", #flag);	\
		}					\
		break;					\
		}
	TOGGLECASE('8', VF_SCHEDULING)
	TOGGLECASE('9', VF_PICKPROC)
#endif
	}
	serial_debug_active = 0;
}

#if DEBUG_SERIAL
void ser_dump_proc()
{
	struct proc *pp;

	for (pp= BEG_PROC_ADDR; pp < END_PROC_ADDR; pp++)
	{
		if (isemptyp(pp))
			continue;
		print_proc_recursive(pp);
	}
}

static void ser_dump_vfs()
{
	/* Notify VFS it has to generate stack traces. Kernel can't do that as
	 * it's not aware of user space threads.
	 */
	mini_notify(proc_addr(KERNEL), VFS_PROC_NR);
}

#endif /* DEBUG_SERIAL */

#if SPROFILE

int arch_init_profile_clock(const u32_t freq)
{
  int r;
  /* Set CMOS timer frequency. */
  outb(RTC_INDEX, RTC_REG_A);
  outb(RTC_IO, RTC_A_DV_OK | freq);
  /* Enable CMOS timer interrupts. */
  outb(RTC_INDEX, RTC_REG_B);
  r = inb(RTC_IO);
  outb(RTC_INDEX, RTC_REG_B); 
  outb(RTC_IO, r | RTC_B_PIE);
  /* Mandatory read of CMOS register to enable timer interrupts. */
  outb(RTC_INDEX, RTC_REG_C);
  inb(RTC_IO);

  return CMOS_CLOCK_IRQ;
}

void arch_stop_profile_clock(void)
{
  int r;
  /* Disable CMOS timer interrupts. */
  outb(RTC_INDEX, RTC_REG_B);
  r = inb(RTC_IO);
  outb(RTC_INDEX, RTC_REG_B);  
  outb(RTC_IO, r & ~RTC_B_PIE);
}

void arch_ack_profile_clock(void)
{
  /* Mandatory read of CMOS register to re-enable timer interrupts. */
  outb(RTC_INDEX, RTC_REG_C);
  inb(RTC_IO);
}

#endif

void arch_do_syscall(struct proc *proc)
{
  /* do_ipc assumes that it's running because of the current process */
  assert(proc == get_cpulocal_var(proc_ptr));
  /* Make the system call, for real this time. */
  assert(proc->p_misc_flags & MF_SC_DEFER);
  proc->p_reg.retreg =
	  do_ipc(proc->p_defer.r1, proc->p_defer.r2, proc->p_defer.r3);
}

struct proc * arch_finish_switch_to_user(void)
{
	char * stk;
	struct proc * p;
    
	stk = (char *)tss[0].sp0;
    
	/* set pointer to the process to run on the stack */
	p = get_cpulocal_var(proc_ptr);
	*((reg_t *)stk) = (reg_t) p;

	/* make sure IF is on in FLAGS so that interrupts won't be disabled
	 * once p's context is restored.
	 */
        p->p_reg.psw |= IF_MASK;

	/* Set TRACEBIT state properly. */
	if(p->p_misc_flags & MF_STEP)
        	p->p_reg.psw |= TRACEBIT;
	else
        	p->p_reg.psw &= ~TRACEBIT;

	return p;
}

void arch_proc_setcontext(struct proc *p, struct stackframe_s *state,
	int isuser, int trap_style)
{
	if(isuser) {
		/* Restore user bits of psw from sc, maintain system bits
		 * from proc.
		 */
		state->psw  =  (state->psw & X86_FLAGS_USER) |
			(p->p_reg.psw & ~X86_FLAGS_USER);
	}

	/* someone wants to totally re-initialize process state */
	assert(sizeof(p->p_reg) == sizeof(*state));
	memcpy(&p->p_reg, state, sizeof(*state));

	/* further code is instructed to not touch the context
	 * any more
	 */
	p->p_misc_flags |= MF_CONTEXT_SET;

	/* on x86 this requires returning using iret (KTS_INT)
	 * so that the full context is restored instead of relying on
	 * the userspace doing it (as it would do on SYSEXIT).
	 * as ESP and EIP are also reset, userspace won't try to
	 * restore bogus context after returning.
	 *
	 * if the process is not blocked, or the kernel will ignore
	 * our trap style, we needn't panic but things will probably
	 * not go well for the process (restored context will be ignored)
	 * and the situation should be debugged.
	 */
	if(!(p->p_rts_flags)) {
		printf("WARNINIG: setting full context of runnable process\n");
		print_proc(p);
		util_stacktrace();
	}
	if(p->p_seg.p_kern_trap_style == KTS_NONE)
		printf("WARNINIG: setting full context of out-of-kernel process\n");
	p->p_seg.p_kern_trap_style = trap_style;
}

void restore_user_context(struct proc *p)
{
	int trap_style = p->p_seg.p_kern_trap_style;
#if 0
#define TYPES 10
	static int restores[TYPES], n = 0;

	if(trap_style >= 0 && trap_style < TYPES)
		restores[trap_style]++;

	if(!(n++ % 500000)) {
		int t;
		for(t = 0; t < TYPES; t++)
			if(restores[t])
				printf("%d: %d   ", t, restores[t]);
		printf("\n");
	}
#endif

	p->p_seg.p_kern_trap_style = KTS_NONE;

	if(trap_style == KTS_SYSENTER) {
		restore_user_context_sysenter(p);
		NOT_REACHABLE;
        }

	if(trap_style == KTS_SYSCALL) {
		restore_user_context_syscall(p);
		NOT_REACHABLE;
	}

        switch(trap_style) {
                case KTS_NONE:
                        panic("no entry trap style known");
                case KTS_INT_HARD:
                case KTS_INT_UM:
                case KTS_FULLCONTEXT:
                case KTS_INT_ORIG:
			restore_user_context_int(p);
			NOT_REACHABLE;
                default:
                        panic("unknown trap style recorded");
                        NOT_REACHABLE;
        }

        NOT_REACHABLE;
}

reg_t arch_get_sp(struct proc *p) { return p->p_reg.sp; }
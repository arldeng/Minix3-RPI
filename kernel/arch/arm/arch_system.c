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
}

void arch_proc_setcontext(struct proc *p, struct stackframe_s *state, int isuser, int trapstyle)
{
    assert(sizeof(p->p_reg) == sizeof(*state));
    memcpy(&p->p_reg, state, sizeof(*state));
    
    /* Further code is instructed to no touch the context
     * any more
     */
    p->p_misc_flags |= MF_CONTEXT_SET;
    
    if (!(p->p_rts_flags)
    {
        
    }
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

void arch_do_syscall(struct proc *proc)
{
  /* do_ipc assumes that it's running because of the current process */
  assert(proc == get_cpulocal_var(proc_ptr));
  /* Make the system call, for real this time. */
  proc->p_reg.retreg =
	  do_ipc(proc->p_defer.retreg, proc->p_defer.r1, proc->p_defer.r2);
}

reg_t svc_stack;

struct proc * arch_finish_switch_to_user(void)
{
	char * stk;
	struct proc * p;
    
	stk = (char *)tss[0].sp0;
    
    svc_stack = (reg_t)stk;
    
	/* set pointer to the process to run on the stack */
	p = get_cpulocal_var(proc_ptr);
	*((reg_t *)stk) = (reg_t) p;
    
    /* Enable interupts */
    p->p_reg.psr &= ~(PSR_I|PSE)

	return p;
}

void fpu_sigcontext(struct proc *pr, struct sigframe *fr, struct sigcontext *sc)
{
}

reg_t arch_get_sp(struct proc *p) { return p->p_reg.sp; }

void get_randomness(struct k_randomness *rand, int sources)
{
}

static void ser_init(void)
{
}

/*===========================================================================*
 *              __switch_address_space              *
 *===========================================================================*
 *
 * Sets the register to the supplied value if it is not already set to the same
 * value in which case it would only result in an extra TLB flush which is not 
 * desirable.
 */

void __switch_address_space(struct proc *p, struct proc **__ptproc)
{
    reg_t orig_ttbr, new_ttbr;
    
    new_ttbr = p->p_seg.p_ttbr;
    if (new_ttbr == 0)
        return;
    
    orig_ttbr = read_ttbr0();
    
    /*
     * Test if ttbr is loaded with the current value to avoid unnecessary
     * TLB flushes
     */
    if (new_ttbr == orig_ttbr)
        return;
    
    write_ttbr0(new_ttbr);
    
    *__ptproc = p;
    
    return;
}

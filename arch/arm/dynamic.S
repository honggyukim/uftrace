#include "utils/asm.h"

	.text
	.align 2

/* universal stack constraint: (SP mod 16) == 0 */
/* frame pointer was saved in the trampoline */
GLOBAL(__dentry__)
	push 	{r0-r3, lr}  /* note that caller already pushed lr */
	ands	r3, lr, #1  /* check lr for ARM/THUMB detection */
	add	r0, sp, #20 /* r0 points to pushed LR  */
	bne	1f
	ldr	r1, [fp]    /* fp (=r11) might point to return address on THUMB */
	ldr	r2, [r0]
	cmp	r1, r2
	moveq	r0, fp
1:
	mov 	r1, lr      /* child ip */
	mov	r2, sp      /* mcount_args */

	bl 	mcount_entry

	pop 	{r0-r3, ip, lr}
	bx	ip
END(__dentry__)


ENTRY(dynamic_return)
	push 	{r0-r3, lr, pc}  /* ensure 8-byte alignment */
	mov	r0, sp
#ifdef HAVE_ARM_HARDFP
	vpush	{d0-d1}
#endif

	bl 	mcount_exit

#if HAVE_ARM_HARDFP
	vpop	{d0-d1}
#endif
	/* update return address (pc) in the stack */
	str 	r0, [sp, #20]
	pop 	{r0-r3, lr, pc}
END(dynamic_return)


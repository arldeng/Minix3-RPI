#ifndef __HW_INTR_ARM_H__
#define __HW_INTR_ARM_H__

#include "kernel/kernel.h"
//void irq_8259_unmask(int irq);
//void irq_8259_mask(int irq);
//void irq_8259_eoi(int irq);
//void irq_handle(int irq);
//void i8259_disable(void);
//void eoi_8259_master(void);
//void eoi_8259_slave(void);

/* legacy PIC */

#define hw_intr_mask(irq)	irq_8259_mask(irq)
#define hw_intr_unmask(irq)	irq_8259_unmask(irq)
#define hw_intr_ack(irq)	irq_8259_eoi(irq)
#define hw_intr_used(irq)
#define hw_intr_not_used(irq)
#define hw_intr_disable_all()

#endif /* __HW_INTR_ARM_H__ */

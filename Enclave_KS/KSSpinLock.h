#ifndef _ENCLAVE_KS_KS_SPINLOCK_H
#define _ENCLAVE_KS_KS_SPINLOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <sgx_spinlock.h>

class KSSpinLock
{
	public:
		KSSpinLock(sgx_spinlock_t *spinlock)
		{
			m_lock = spinlock;
			sgx_spin_lock(spinlock);
		}

		virtual ~KSSpinLock(){
			sgx_spin_unlock(m_lock);
		}

		private:
			sgx_spinlock_t *m_lock = NULL;
};
#endif
#include "KEVENT_or_KMUTEX_init.h"

BOOLEAN K_object_init_check_also_lock_ifyouwant(PK_EVENT_or_MUTEX_struct Insert_your_OBJECT_struct_addr, BOOLEAN is_you_want_lock) {
	if (Insert_your_OBJECT_struct_addr == NULL) return FALSE;


	if (Insert_your_OBJECT_struct_addr->object_name == (K_object_status)K_MUTEX) {

		if (Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object == NULL) {
			Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, sizeof(KMUTEX), 'Mutx');
			if (Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object == NULL) return FALSE;

			// KMUTEX 초기화 
			KeInitializeMutex((PKMUTEX)Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object, 0);
		}


	}
	else if (Insert_your_OBJECT_struct_addr->object_name == (K_object_status)K_EVENT) {

		if (Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object == NULL) {
			Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEVENT), 'Evnt');
			if (Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object == NULL) return FALSE;

			// KEVENT 초기화 
			KeInitializeEvent((PKEVENT)Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object, SynchronizationEvent, FALSE);
		}
	}
	else {
		return FALSE;
	}




	if (is_you_want_lock) {
		
		if (Insert_your_OBJECT_struct_addr->object_name == (K_object_status)K_MUTEX) {
			KeWaitForSingleObject(Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object, Executive, KernelMode, FALSE, NULL);
			Insert_your_OBJECT_struct_addr->is_locking = TRUE;
		}
		else if (Insert_your_OBJECT_struct_addr->object_name == (K_object_status)K_EVENT) {
			// EVENT는 미리 TRUE걸어야함 
			Insert_your_OBJECT_struct_addr->is_locking = TRUE;
			KeWaitForSingleObject(Insert_your_OBJECT_struct_addr->K_EVENT_or_MUTEX_object, Executive, KernelMode, FALSE, NULL);
			//Insert_your_OBJECT_struct_addr->is_locking = FALSE;
		}
		

	}

	return TRUE;
}

BOOLEAN K_object_lock_Release(PK_EVENT_or_MUTEX_struct Insert_your_OBJECT_addr) {
	if (Insert_your_OBJECT_addr == NULL || Insert_your_OBJECT_addr->K_EVENT_or_MUTEX_object == NULL) return FALSE;

	if (Insert_your_OBJECT_addr->is_locking == TRUE) {
		if (Insert_your_OBJECT_addr->object_name == (K_object_status)K_MUTEX) {
			KeReleaseMutex((PKMUTEX)Insert_your_OBJECT_addr->K_EVENT_or_MUTEX_object, FALSE);
		}
		else if (Insert_your_OBJECT_addr->object_name == (K_object_status)K_EVENT) {
			KeSetEvent((PKEVENT)Insert_your_OBJECT_addr->K_EVENT_or_MUTEX_object, 0, FALSE); 
		}
	}

	return TRUE;
}
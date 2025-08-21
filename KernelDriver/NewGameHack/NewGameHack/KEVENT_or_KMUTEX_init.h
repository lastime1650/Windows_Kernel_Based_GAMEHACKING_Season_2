#ifndef KEVENT_or_KMUTEX_init_H
#define KEVENT_or_KMUTEX_init_H

#pragma warning(disable: 4996)

#include <ntifs.h>

typedef enum K_object_status{
	K_EVENT=1,
	K_MUTEX
}K_object_status;

typedef struct K_EVENT_or_MUTEX_struct {

	PUCHAR K_EVENT_or_MUTEX_object;

	

	K_object_status object_name;

	BOOLEAN is_locking; // 현재 잠금중인가? 

}K_EVENT_or_MUTEX_struct, *PK_EVENT_or_MUTEX_struct;

BOOLEAN K_object_init_check_also_lock_ifyouwant(PK_EVENT_or_MUTEX_struct Insert_your_OBJECT_addr,BOOLEAN is_you_want_lock);

BOOLEAN K_object_lock_Release(PK_EVENT_or_MUTEX_struct Insert_your_OBJECT_addr);

#endif // !KEVENT_or_KMUTEX_init_H

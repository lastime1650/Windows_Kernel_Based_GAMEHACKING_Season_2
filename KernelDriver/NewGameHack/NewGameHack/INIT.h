#pragma once
#ifndef IOCTL_INIT_H
#include <ntifs.h>
#include "APC.h"
typedef struct _INIT {

	APC APC_info;

	NTSTATUS Output;

}INIT, * PINIT;

NTSTATUS INITALIZE_GAME_HACK(PINIT information);

#endif
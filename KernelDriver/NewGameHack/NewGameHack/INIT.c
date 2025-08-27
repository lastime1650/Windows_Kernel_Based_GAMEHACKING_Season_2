#include "INIT.h"
/*
	INITIALIZE DO-ONCE 처리
*/
NTSTATUS INITALIZE_GAME_HACK(PINIT information) {

	NTSTATUS status;

	// APC 등록 -> 비동기적으로 { 커널 -> 유저 } 응답
	status = INITIALIZE_APC(
		information->APC_info.ThreadID,
		information->APC_info.User_APCHandler
	);


	return status;
}
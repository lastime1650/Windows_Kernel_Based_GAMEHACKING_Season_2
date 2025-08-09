#ifndef WS_H
#define WS_H

#include <unordered_map>
#include <shared_mutex>
#include <uwebsockets/App.h>

// cmd
typedef enum CMD {
	newscan,
	addressscan,
	memdumping,
	dll_injection,
	set_hwbp,
	memwrite,
	memallscan
}CMD;

// Struct
struct WebSocketStruct {
	uint64_t SessionId; // Id값을 통해 적절한 WS 오브젝트에 접근
};

extern std::unordered_map<uint64_t, uWS::WebSocket<false, true, WebSocketStruct>*> ws_clients; // { SessionId, WS오브젝트 } 형태 MAP 
extern std::shared_mutex ws_mutex; // 상호배제

uint64_t Get_Random_Key();

#endif
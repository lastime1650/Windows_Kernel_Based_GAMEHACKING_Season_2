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
	uint64_t SessionId; // Id���� ���� ������ WS ������Ʈ�� ����
};

extern std::unordered_map<uint64_t, uWS::WebSocket<false, true, WebSocketStruct>*> ws_clients; // { SessionId, WS������Ʈ } ���� MAP 
extern std::shared_mutex ws_mutex; // ��ȣ����

uint64_t Get_Random_Key();

#endif
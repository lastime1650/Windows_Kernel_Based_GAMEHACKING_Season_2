#include <uwebsockets/App.h>
#include <rapidjson/document.h>
#include <iostream>

#include "WebSocket.h"

std::unordered_map<uint64_t, uWS::WebSocket<false, true, WebSocketStruct>*> ws_clients; // { SessionId, WS오브젝트 } 형태 MAP 
std::shared_mutex ws_mutex; // 상호배제

#include "IOCTL_Manager.h"

IOCTL_Manager IOCTL_manage = IOCTL_Manager();
#include "base64.h"
int main() {
    
    /*DWORD test = (DWORD)123123123;

    std::string encoded = base64_encode((PUCHAR) &test, sizeof(PUCHAR));
    std::cout << "-> " << encoded << std::endl;

    std::string decoded = base64_decode(encoded);
    
    std::cout << "-> " << decoded << std::endl;

    DWORD data = 0;
    memcpy(&data, decoded.c_str(), 4);
    std::cout << "-> " << data << std::endl;*/

    uWS::App().ws<WebSocketStruct>("/*", {
        .maxPayloadLength = 500 * 1024 * 1024,  // 100MB 제한 설정
        .open = [](uWS::WebSocket<false, true, WebSocketStruct>* ws) {
            uint64_t SessionId = Get_Random_Key();

            ws->getUserData()->SessionId = SessionId;

            ws_clients[SessionId] = ws;

            std::cout << "연결된 세션:" << ws_clients[SessionId] << std::endl;

        },
        .message = [](uWS::WebSocket<false, true, WebSocketStruct>* ws, std::string_view message, uWS::OpCode opCode) {
            rapidjson::Document data;
            if (data.Parse(message.data(), message.size()).HasParseError()) {
                ws->send("Invalid JSON", uWS::OpCode::TEXT);
                return;
            }
            
            if (!data.HasMember("cmd")) {
                ws->send("No there 'cmd' Key in Request JSON", uWS::OpCode::TEXT);
                return;
            }

            CMD command = static_cast<CMD>( data["cmd"].GetUint() );

            std::string OutputJSON_TEXT;

            switch (command) {
            case newscan:
            {
                
                OutputJSON_TEXT = IOCTL_manage.NewScanning(data);
                break;
            }
            case addressscan:
            {
                OutputJSON_TEXT = IOCTL_manage.AddressScanning(data);
                break;
            }
            case memdumping:
            {
                OutputJSON_TEXT = IOCTL_manage.MemDumping(data);
                break;
            }
            case dll_injection:
            {
                OutputJSON_TEXT = IOCTL_manage.DLL_Injection(data);
                break;
            }
            case set_hwbp:
            {
                OutputJSON_TEXT = IOCTL_manage.Set_HW_BP(data);
                break;
            }
            case memwrite:
            {
                OutputJSON_TEXT = IOCTL_manage.MemWriting(data);
                break;
            }
            case memallscan:
            {
                OutputJSON_TEXT = IOCTL_manage.MemAllScanning(data);
                break;
            }
            default:
            {
                ws->send("I can't understand CMD !!!!!!!!!! :< ", uWS::OpCode::TEXT);
                return;
            }
            }

            ws->send(OutputJSON_TEXT, uWS::OpCode::TEXT);
            return;
        },
        .close = [](uWS::WebSocket<false, true, WebSocketStruct>* ws, int, std::string_view) {
            
            uint64_t SessionId = ws->getUserData()->SessionId;

            ws_clients.erase(SessionId);
        
        }
    }).listen(9001, [](auto* token) {
        if (token) {
            std::cout << "Listening on port 9001" << std::endl;
        }
        }).run();

    return 0;
}

#include <chrono>
#include <cstdint>

uint64_t Get_Random_Key() {
    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();

    return static_cast<uint64_t>(us);
}
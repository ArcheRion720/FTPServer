#pragma once

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif

    #include <windows.h>
    #include <winsock2.h>
    #include <ws2def.h>
    #include <MSWSock.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>

    #pragma comment(lib,"user32.lib") 
    #pragma comment(lib,"WS2_32")
    #pragma comment(lib,"Mswsock.lib")
    #pragma comment(lib,"IPHLPAPI.lib")
#endif

#include <string>
#include <filesystem>
#include <string_view>
#include "ftp_enums.hpp"
#include "ftp_user.hpp"

struct overlapped_io;

struct ftp_session
{
    FTP_AUTH_STATUS auth;
    FTP_DATA_MODE data_mode;
    SOCKET cmd;
    SOCKET ldata;
    HANDLE wait_for_data;
    overlapped_io* command_io;
    overlapped_io* remote_io;
    std::filesystem::path current_path;
    std::string username;
    ftp_user* user;
};

struct server_state
{
    SOCKET listener;
    HANDLE iocp;
    HANDLE shutdown_event;
    std::string config_path;
};

enum class IO_OP_TYPE
{
    IO_ACCEPT,
    IO_SEND,
    IO_RECV,
    IO_CONNECT,
    IO_DISCONNECT,
    IO_DATA_PASV_OPEN,
    IO_DATA_CONNECT,
    IO_REMOTE_DISCONNECT,
    IO_REMOTE_ANNOUNCE_END,
    IO_WRITE_FILE
};

struct overlapped_io
{
    OVERLAPPED overlap;
    SOCKET socket;
    WSABUF buffer;
    IO_OP_TYPE type;
    ftp_session* session;
    server_state& server;
    char bytes[16384];
};

bool CreateServer(server_state& state, addrinfo* info);
void StartAcceptEx(server_state& server);
DWORD WINAPI FTPWorkerThread(LPVOID lpParam);
bool SendResponse(overlapped_io* io, FTP_RETURN_CODE code, std::string message);
void RegisterFTPHandlers();

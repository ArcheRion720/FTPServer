#include "ftp_win.hpp"
#include "ftp_handlers.hpp"
#include "ftp_user.hpp"
#include <sstream>
#include <iostream>
#include <format>
#include <filesystem>
#include <iomanip>

bool CreateServer(server_state& state, addrinfo* info)
{
    state.listener = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if(state.listener == INVALID_SOCKET)
    {
        WSACleanup();
        return false;
    }

    if(!::bind(state.listener, info->ai_addr, (int)info->ai_addrlen))
    {
        if(!::listen(state.listener, SOMAXCONN))
        {
            if((state.iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0)) != NULL)
            {
                if(CreateIoCompletionPort((HANDLE)state.listener, state.iocp, NULL, 4) != NULL)
                    return true;

                CloseHandle(state.iocp);
            }
        }
    }
    
    closesocket(state.listener);
    return false;
}

bool CreateOverlappedIOObject(server_state& server, overlapped_io** io, ftp_session* session = nullptr)
{
    overlapped_io* io_obj = new overlapped_io{.server = server};
    if(io == nullptr)
        return false;

    if(session == nullptr)
    {
        session = new ftp_session{};
        if(session == nullptr)
            return false;

        session->auth = FTP_AUTH_STATUS::AWAIT_USER;
        session->data_mode = FTP_DATA_MODE::NONE;
        session->ldata = INVALID_SOCKET;

        session->current_path = ".";
        session->wait_for_data = CreateEvent(NULL, TRUE, FALSE, NULL);
    }

    ZeroMemory(&io_obj->overlap, sizeof(OVERLAPPED));
    ZeroMemory(&io_obj->bytes, 16384);
    ZeroMemory(&io_obj->buffer, sizeof(WSABUF));

    session->remote_io = nullptr;
    io_obj->session = session;

    *io = io_obj;
    return true;
}

void StartAcceptEx(server_state& server)
{
    SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if(sock == INVALID_SOCKET)
        return;

    overlapped_io* io;
    if(!CreateOverlappedIOObject(server, &io))
    {
        closesocket(sock);
        return;
    }

    io->socket = sock;
    io->buffer.buf = io->bytes;
    io->buffer.len = 16384;
    io->type = IO_OP_TYPE::IO_ACCEPT;

    DWORD bytes_recv = 0;
    while(AcceptEx(
        server.listener, 
        sock, 
        io->buffer.buf, 
        0, 
        sizeof(SOCKADDR_IN) + 16,
        sizeof(SOCKADDR_IN) + 16,
        &bytes_recv,
        (LPOVERLAPPED)io) == false)
    {
        if(WSAGetLastError() == WSA_IO_PENDING)
            break;

        throw;
    }
}

void ShutdownConnection(overlapped_io* io)
{
    io->type = IO_OP_TYPE::IO_DISCONNECT;
    if(!SendResponse(io, FTP_RETURN_CODE::SHUTTING_DOWN, "Unrecoverable error"))
    {
        closesocket(io->socket);
    }
}

DWORD WINAPI FTPWorkerThread(LPVOID lpParam)
{
    server_state* server = (server_state*)lpParam;
    SOCKET listener = server->listener;
    HANDLE compl_port = server->iocp;

    DWORD bytes_transferred;
    ULONG_PTR completion_key;
    overlapped_io* io;

    while(true)
    {
        BOOL result = GetQueuedCompletionStatus(
            compl_port, 
            &bytes_transferred,
            &completion_key,
            (LPOVERLAPPED*)&io,
            INFINITE);

        if(!result)
        {
            auto err = GetLastError();
            if((err == WAIT_TIMEOUT) || (err == ERROR_NETNAME_DELETED))
            {
                closesocket(io->socket);
                delete io;
                continue;
            }

            return 0;
        }

        switch (io->type)
        {
            case IO_OP_TYPE::IO_ACCEPT:
            {
                StartAcceptEx(io->server);
                setsockopt(io->socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&(listener), sizeof(SOCKET));

                ZeroMemory(io->bytes, 16384);

                CreateIoCompletionPort((HANDLE)io->socket, compl_port, NULL, 0);
                io->type = IO_OP_TYPE::IO_SEND;
                io->session->command_io = io;
                io->session->cmd = io->socket;

                if(!SendResponse(io, FTP_RETURN_CODE::READY_FOR_NEW_USER, "(test ftp)") && WSAGetLastError() != WSA_IO_PENDING)
                {
                    closesocket(io->socket);
                    delete io;
                    continue;
                }
                
                break;
            }
            case IO_OP_TYPE::IO_RECV:
            {
                if(bytes_transferred == 0)
                {
                    ShutdownConnection(io);
                    continue;
                }

                if(!HandleIncomingMessage(io, bytes_transferred) && WSAGetLastError() != WSA_IO_PENDING)
                {
                    ShutdownConnection(io);
                    continue;
                }

                break;
            }
            case IO_OP_TYPE::IO_SEND:
            {
                if(bytes_transferred == 0)
                {
                    ShutdownConnection(io);
                    continue;
                }

                io->type = IO_OP_TYPE::IO_RECV;
                io->buffer.buf = io->buffer.buf;
                io->buffer.len = 16384;

                DWORD bytes_recv, dwFlag;
                int recv = WSARecv(io->socket, &io->buffer, 1, &bytes_recv, &dwFlag, &(io->overlap), 0);
                if(recv == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
                    ShutdownConnection(io);

                break;
            }
            case IO_OP_TYPE::IO_DATA_PASV_OPEN:
            {
                if(bytes_transferred == 0)
                {
                    ShutdownConnection(io);
                    continue;
                }

                SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
                if(sock == INVALID_SOCKET)
                    throw;

                overlapped_io* data_io;
                if(!CreateOverlappedIOObject(io->server, &data_io, io->session))
                    throw;

                data_io->socket = sock;
                data_io->buffer.buf = data_io->bytes;
                data_io->buffer.len = 16384;
                data_io->type = IO_OP_TYPE::IO_DATA_CONNECT;

                DWORD dwRecv = 0;
                if(AcceptEx(
                    io->session->ldata,
                    sock,
                    data_io->buffer.buf,
                    0, 
                    sizeof(SOCKADDR_IN) + 16,
                    sizeof(SOCKADDR_IN) + 16,
                    &dwRecv,
                    (LPOVERLAPPED)data_io) == false)
                {
                    if(WSAGetLastError() != WSA_IO_PENDING)
                    {
                        int x = WSAGetLastError();
                        throw;
                    }
                }

                io->type = IO_OP_TYPE::IO_RECV;
                io->buffer.buf = io->buffer.buf;
                io->buffer.len = 16384;

                DWORD dwFlag;
                int recv = WSARecv(io->socket, &io->buffer, 1, &dwRecv, &dwFlag, &(io->overlap), 0);
                if(recv == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
                    throw;

                break;
            }
            case IO_OP_TYPE::IO_DATA_CONNECT:
            {
                io->session->remote_io = io;
                CreateIoCompletionPort((HANDLE)io->socket, compl_port, NULL, 0);
                SetEvent(io->session->wait_for_data);
                break;
            }
            case IO_OP_TYPE::IO_REMOTE_ANNOUNCE_END:
            {
                io->session->command_io->type = IO_OP_TYPE::IO_SEND;
                if(!SendResponse(io->session->command_io, FTP_RETURN_CODE::CLOSING_DATA, "Transfer Complete."))
                {
                    closesocket(io->socket);
                    delete io;
                }
            }
            case IO_OP_TYPE::IO_REMOTE_DISCONNECT:
            {
                closesocket(io->socket);
                if(io->session->ldata != INVALID_SOCKET)
                {
                    closesocket(io->session->ldata);
                    io->session->ldata = INVALID_SOCKET;
                }

                io->session->data_mode = FTP_DATA_MODE::NONE;
                ResetEvent(io->session->wait_for_data);
                delete io;
                continue;
            }
            case IO_OP_TYPE::IO_DISCONNECT:
            {
                closesocket(io->socket);
                continue;
            }

            default:
                break;
        }
    }
}
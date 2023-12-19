#include "ftp_handlers.hpp"
#include <map>
#include <string>
#include <sstream>
#include <algorithm>
#include <functional>

static std::map<std::string, ftp_handler> ftp_handlers;

extern bool CreateOverlappedIOObject(server_state& server, overlapped_io** io, ftp_session* session = nullptr);

bool HandleIncomingMessage(overlapped_io* io, int bytes)
{
    if(bytes == 0)
        return false;

    // std::vector<std::string> args{};
    std::string command;

    std::stringstream ss{std::string(io->buffer.buf, bytes)};
    if(!(ss >> command))
    {
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::UNKNOWN_COMMAND, "Unknown command.");
    }

    std::string args;
    ss >> std::quoted(args);

    auto handler = (ftp_handlers.contains(command) ? ftp_handlers[command] : nullptr);
    if(handler == nullptr)
    {
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::UNKNOWN_COMMAND, "Unknown command.");
    }

    return handler(io, bytes, args);
}

void RegisterFTPHandler(std::string command, ftp_handler handler)
{
    ftp_handlers.emplace(command, handler);
}

bool SendResponse(overlapped_io* io, FTP_RETURN_CODE code, std::string message)
{
    std::string msg = std::format("{} {}\r\n", (int)code, message);

    io->buffer.buf = io->bytes;
    msg.copy(io->bytes, msg.length());

    io->buffer.len = msg.length();

    DWORD bytes_sent = 0;
    int sent = WSASend(io->socket, &io->buffer, 1, &bytes_sent, 0, &(io->overlap), 0);
    if(sent == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
    {
        return false;
    }

    return true;
}

bool RequireAuthorization(overlapped_io* io, bool& authorized)
{
    if(io->session->auth != FTP_AUTH_STATUS::AUTHORIZED)
    {
        authorized = false;
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::NOT_LOGGED_IN, "Please login with USER and PASS.");
    }

    authorized = true;
    return true;
}

bool RequireDataConnection(overlapped_io* io, bool& proceed)
{
    if(io->session->data_mode == FTP_DATA_MODE::NONE)
    {
        proceed = false;
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::CANT_OPEN_DATA, "Use PORT or PASV first.");
    }

    proceed = true;
    return true;
}

bool PerformFileWrite(HANDLE file, overlapped_io* remote)
{
    int recv = 0;
    DWORD written;
    while((recv = ::recv(remote->socket, remote->buffer.buf, remote->buffer.len, 0)) > 0)
    {
        if(!WriteFile(file, remote->buffer.buf, recv, &written, NULL))
        {
            int x = GetLastError();
            CloseHandle(file);
            return false;
        }
    }

    if(recv < 0)
    {
        CloseHandle(file);
        return false;
    }

    closesocket(remote->socket);
    if(remote->session->ldata != INVALID_SOCKET)
    {
        closesocket(remote->session->ldata);
        remote->session->ldata = INVALID_SOCKET;
    }

    remote->session->data_mode = FTP_DATA_MODE::NONE;
    ResetEvent(remote->session->wait_for_data);
    delete remote;

    CloseHandle(file);
    return true;
}

#define FTP_ASSERT(REQ_FUNC) \
    bool auth##REQ_FUNC; \
    if(!REQ_FUNC(io, auth##REQ_FUNC)) return false; \
    if(!auth##REQ_FUNC) return true;

#define FTP_CLOSE_DATA(io) \
    if(io->session->remote_io->socket != INVALID_SOCKET) closesocket(io->session->remote_io->socket); \
    ResetEvent(io->session->wait_for_data);

void RegisterFTPHandlers()
    {
    RegisterFTPHandler("USER", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        if(io->session->auth == FTP_AUTH_STATUS::AUTHORIZED)
        {
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(io, FTP_RETURN_CODE::NOT_LOGGED_IN, "Can't change to another user.");
        }

        if(args.length() == 0)
        {
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(io, FTP_RETURN_CODE::SYNTAX_ERROR, "Provide name of USER.");
        }

        io->session->username = args;
        io->session->auth = FTP_AUTH_STATUS::AWAIT_PASS;

        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::USER_NEED_PASS, "Please specify the password.");
    });

    RegisterFTPHandler("PASS", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        switch(io->session->auth)
        {
            case FTP_AUTH_STATUS::AUTHORIZED:
            {
                io->type = IO_OP_TYPE::IO_SEND;
                return SendResponse(io, FTP_RETURN_CODE::LOGIN_SUCCESSFUL, "Already logged in.");
            }
            case FTP_AUTH_STATUS::AWAIT_USER:
            {
                io->type = IO_OP_TYPE::IO_SEND;
                return SendResponse(io, FTP_RETURN_CODE::BAD_SEQUENCE, "Login with USER first.");
            }
            case FTP_AUTH_STATUS::AWAIT_PASS:
            {
                ftp_user* user;
                if(GetFTPUser(io->session->username, &user) &&
                    (user->hash == 0 ||
                        (args.length() != 0 &&
                        user->hash == GetPasswordHash(args)))
                )
                {
                    io->session->auth = FTP_AUTH_STATUS::AUTHORIZED;
                    io->session->user = user;
                    io->type = IO_OP_TYPE::IO_SEND;
                    return SendResponse(io, FTP_RETURN_CODE::LOGIN_SUCCESSFUL, "Login successful.");
                }
                else
                {
                    io->session->auth = FTP_AUTH_STATUS::AWAIT_USER;
                    io->type = IO_OP_TYPE::IO_SEND;
                    return SendResponse(io, FTP_RETURN_CODE::NOT_LOGGED_IN, "Login incorrect.");
                }
            }
            default:
                return false;
        }
    });

    RegisterFTPHandler("QUIT", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        io->type = IO_OP_TYPE::IO_DISCONNECT;
        return SendResponse(io, FTP_RETURN_CODE::GOODBYE, "Goodbye.");
    });

    RegisterFTPHandler("NOOP", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::SUCCESS, "Command OK.");
    });

    RegisterFTPHandler("PORT", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        SOCKET datasock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if(datasock == INVALID_SOCKET)
            return false;

        std::stringstream ss{args};
        int data[6];
        for(int i = 0; i < 6 && ss.good(); i++)
        {
            ss >> data[i];
            ss.ignore();
        }

        DWORD dwbytes = 0;
        GUID guid = WSAID_CONNECTEX;
        LPFN_CONNECTEX ConnectEx = NULL;
        if(WSAIoctl(
            datasock,
            SIO_GET_EXTENSION_FUNCTION_POINTER, 
            (void*)&guid, 
            sizeof(guid), 
            (void*)&ConnectEx, sizeof(ConnectEx),
            (LPDWORD)&dwbytes, NULL, NULL) != 0)
        {
            return false;
        }

        struct addrinfo hints, *addr;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        std::string addrstr = std::format("{}.{}.{}.{}", data[0], data[1], data[2], data[3]);
        std::string portstr = std::to_string(data[4] * 256 + data[5]);
        if(getaddrinfo(addrstr.c_str(), portstr.c_str(), &hints, &addr) != 0)
            return false;

        {
            sockaddr_in temp;
            ZeroMemory(&temp, sizeof(sockaddr_in));
            temp.sin_family = AF_INET;
            temp.sin_addr.s_addr = INADDR_ANY;
            temp.sin_port = 0;
            if(::bind(datasock, (SOCKADDR*)&temp, sizeof(temp)) == SOCKET_ERROR)
            {
                return false;
            }
        }

        if(ConnectEx == NULL)
            return false;

        overlapped_io* data_io;
        if(!CreateOverlappedIOObject(io->server, &data_io, io->session))
            throw;

        if(!CreateIoCompletionPort((HANDLE)datasock, io->server.iocp, 0, 0))
            return false;

        data_io->socket = datasock;
        data_io->buffer.buf = data_io->bytes;
        data_io->buffer.len = 16384;
        data_io->type = IO_OP_TYPE::IO_DATA_CONNECT;

        if(!ConnectEx(datasock,
            addr->ai_addr, 
            addr->ai_addrlen, 
            NULL, 
            0, NULL, (LPOVERLAPPED)data_io) && WSAGetLastError() != WSA_IO_PENDING)
        {
            int x = WSAGetLastError();
            return false;
        }

        io->session->data_mode = FTP_DATA_MODE::PORT;
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::SUCCESS, "PORT command sucessful. Consider using PASV.");
    });

    RegisterFTPHandler("PASV", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        FTP_ASSERT(RequireAuthorization);

        sockaddr server_addr;
        int len = sizeof(sockaddr);
        if(getsockname(io->server.listener, &server_addr, &len) != 0)
            return false;

        if(server_addr.sa_family != AF_INET)
            return false;

        sockaddr_in* addr = (sockaddr_in*)&server_addr;
        addr->sin_port = 0;

        SOCKET datasock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if(datasock == INVALID_SOCKET)
            return false;

        if(!::bind(datasock, &server_addr, len))
        {
            if(!::listen(datasock, 1))
            {
                if(CreateIoCompletionPort((HANDLE)datasock, io->server.iocp, 0, 0))
                {
                    len = sizeof(sockaddr);
                    if(getsockname(datasock, &server_addr, &len) != 0)
                    {
                        closesocket(datasock);
                        return false;
                    }

                    io->session->data_mode = FTP_DATA_MODE::PASV;
                    io->session->ldata = datasock;

                    auto s = std::format("Entering Passive Mode ({},{},{},{},{},{}).",
                        addr->sin_addr.S_un.S_un_b.s_b1,
                        addr->sin_addr.S_un.S_un_b.s_b2,
                        addr->sin_addr.S_un.S_un_b.s_b3,
                        addr->sin_addr.S_un.S_un_b.s_b4,
                        addr->sin_port % 256,
                        addr->sin_port / 256);

                    io->type = IO_OP_TYPE::IO_DATA_PASV_OPEN;
                    return SendResponse(io, FTP_RETURN_CODE::ENTER_PASV_MODE, s);
                }
            }
        }

        closesocket(datasock);
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::CANT_OPEN_DATA, "Cannot open data connection.");
    });

    RegisterFTPHandler("SYST", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::NAME, "MS-DOS");
    });

    RegisterFTPHandler("LIST", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        FTP_ASSERT(RequireAuthorization);

        io->type = IO_OP_TYPE::IO_SEND;
        if(!SendResponse(io, FTP_RETURN_CODE::OPENING_DATA_SOCK, "Here comes the directory listing."))
            return false;

        std::stringstream ss;
        auto p = io->session->user->base / io->session->current_path;

        for(auto file : std::filesystem::directory_iterator{p})
        {
            if(!file.is_directory() && !file.is_regular_file())
                continue;

            auto t = file.last_write_time();
            ss << std::format("{:%d.%m.%Y %R} ", t);
            if(file.is_regular_file())
                ss << std::format("{} ", file.file_size());
            else if(file.is_directory())
                ss << "<DIR> ";

            ss << file.path().filename().string();
            ss << "\r\n";
        }

        WaitForSingleObject(io->session->wait_for_data, INFINITE);

        std::string msg = ss.str();

        overlapped_io* remote = io->session->remote_io;

        remote->buffer.buf = remote->bytes;
        msg.copy(remote->bytes, msg.length());
        remote->buffer.len = msg.length();
        remote->type = IO_OP_TYPE::IO_REMOTE_DISCONNECT;

        if(WSASend(remote->socket, &remote->buffer, 1, NULL, 0, &remote->overlap, 0) == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
            return false;

        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::CLOSING_DATA, "Directory send OK.");
    });

    RegisterFTPHandler("TYPE", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        if(args.length() != 1)
        {
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(io, FTP_RETURN_CODE::SYNTAX_ERROR, "Unknown TYPE command.");
        }

        switch(args[0])
        {
            case 'I':
            case 'A':
                io->type = IO_OP_TYPE::IO_SEND;
                return SendResponse(io, FTP_RETURN_CODE::SUCCESS, "Mode set.");
            default:
                io->type = IO_OP_TYPE::IO_SEND;
                return SendResponse(io, FTP_RETURN_CODE::SYNTAX_ERROR, "Unknown TYPE command.");
        }
    });

    RegisterFTPHandler("PWD", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        FTP_ASSERT(RequireAuthorization);

        std::string resp;
        if(io->session->current_path == ".")
        {
            resp = "\"/\" is the current directory.";
        }
        else
        {
            resp = std::format("\"/{}\" is the current directory.", io->session->current_path.string());
        }

        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::PATHNAME_CREATED, resp);
    });

    RegisterFTPHandler("CWD", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        FTP_ASSERT(RequireAuthorization);

        if(std::filesystem::path{args}.is_absolute())
        {
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_OP, "Failed to change directory.");
        }

        if(args.starts_with('/'))
        {
            args.erase(0, args.find_first_not_of("/"));
            std::filesystem::path target{args};
            std::filesystem::path path{io->session->user->base / target};
            if(std::filesystem::exists(path) && std::filesystem::is_directory(path))
            {
                io->session->current_path = std::filesystem::relative(std::filesystem::canonical(path), io->session->user->base);
                io->type = IO_OP_TYPE::IO_SEND;
                return SendResponse(io, FTP_RETURN_CODE::FILE_ACTION_OK, "Directory successfully changed.");
            }
        }

        std::filesystem::path target{io->session->current_path / args};
        std::filesystem::path path = io->session->user->base / target;
        if(std::filesystem::exists(path) && std::filesystem::is_directory(path))
        {
            io->session->current_path = std::filesystem::relative(std::filesystem::canonical(path), io->session->user->base);
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(io, FTP_RETURN_CODE::FILE_ACTION_OK, "Directory successfully changed.");
        }

        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_OP, "Failed to change directory.");
    });

    RegisterFTPHandler("RETR", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        FTP_ASSERT(RequireAuthorization);
        FTP_ASSERT(RequireDataConnection);

        std::filesystem::path target{io->session->user->base / io->session->current_path / args};
        if(std::filesystem::exists(target) && std::filesystem::is_regular_file(target))
        {
            std::string pstr = target.string();

            HANDLE file = CreateFileA(pstr.c_str(),
                GENERIC_READ, 
                FILE_SHARE_READ, 
                NULL, 
                OPEN_EXISTING, 
                FILE_ATTRIBUTE_NORMAL, 
                NULL);

            if(file == INVALID_HANDLE_VALUE)
            {
                FTP_CLOSE_DATA(io);
                io->type = IO_OP_TYPE::IO_SEND;
                CloseHandle(file);
                return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_OP, "Failed to open file.");
            }

            LARGE_INTEGER size;
            if(!GetFileSizeEx(file, &size))
            {
                FTP_CLOSE_DATA(io);
                io->type = IO_OP_TYPE::IO_SEND;
                CloseHandle(file);
                return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_OP, "Failed to open file.");
            }

            io->type = IO_OP_TYPE::IO_SEND;
            if(!SendResponse(io, 
                FTP_RETURN_CODE::OPENING_DATA_SOCK, 
                std::format("Reading file {} ({} bytes)", args, (int)size.LowPart))
            )
                return false;

            WaitForSingleObject(io->session->wait_for_data, INFINITE);

            overlapped_io* remote = io->session->remote_io;
            remote->buffer.buf = remote->bytes;
            remote->buffer.len = 16384;
            remote->type = IO_OP_TYPE::IO_REMOTE_ANNOUNCE_END;

            if(!TransmitFile(remote->socket, file, size.LowPart, 0, (LPOVERLAPPED)remote, NULL, TF_DISCONNECT) && WSAGetLastError() != WSA_IO_PENDING)
            {
                return false;
            }

            return true;
        }
        
        WaitForSingleObject(io->session->wait_for_data, INFINITE);
        FTP_CLOSE_DATA(io);

        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_OP, "File not found.");
    });

    RegisterFTPHandler("STOR", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        FTP_ASSERT(RequireAuthorization);
        FTP_ASSERT(RequireDataConnection);

        std::filesystem::path target{io->session->user->base / io->session->current_path / args};
        std::string pstr = target.string();

        io->type = IO_OP_TYPE::IO_SEND;
        if(!SendResponse(io, FTP_RETURN_CODE::OPENING_DATA_SOCK, "Ok to send data."))
            return false;

        HANDLE file = CreateFileA(pstr.c_str(),
            GENERIC_WRITE, 
            0, 
            NULL, 
            OPEN_ALWAYS, 
            FILE_ATTRIBUTE_NORMAL, 
            NULL);

        if(file == NULL)
        {
            if(!SendResponse(io, FTP_RETURN_CODE::OPENING_DATA_SOCK, "Ok to send data."))
                return false;
        }

        WaitForSingleObject(io->session->wait_for_data, INFINITE);

        overlapped_io* remote = io->session->remote_io;
        remote->buffer.buf = remote->bytes;
        remote->buffer.len = 16384;

        //close remote

        if(PerformFileWrite(file, remote))
        {
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(io, FTP_RETURN_CODE::CLOSING_DATA, "Transfer Complete.");
        }

        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_SAVE, "Transfer Failed.");
    });

    RegisterFTPHandler("APPE", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        FTP_ASSERT(RequireAuthorization);
        FTP_ASSERT(RequireDataConnection);

        std::filesystem::path target{io->session->user->base / io->session->current_path / args};
        std::string pstr = target.string();

        HANDLE file = CreateFileA(pstr.c_str(),
            FILE_APPEND_DATA, 
            0, 
            NULL, 
            OPEN_ALWAYS, 
            FILE_ATTRIBUTE_NORMAL, 
            NULL);

        if(file == NULL)
        {
            if(!SendResponse(io, FTP_RETURN_CODE::OPENING_DATA_SOCK, "Ok to send data."))
                return false;
        }

        WaitForSingleObject(io->session->wait_for_data, INFINITE);

        overlapped_io* remote = io->session->remote_io;
        remote->buffer.buf = remote->bytes;
        remote->buffer.len = 16384;

        if(PerformFileWrite(file, remote))
        {
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(io, FTP_RETURN_CODE::CLOSING_DATA, "Transfer Complete.");
        }

        io->type = IO_OP_TYPE::IO_SEND;
        return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_SAVE, "Transfer Failed.");
    });

    RegisterFTPHandler("MKD", [](overlapped_io* io, int bytes, std::string& args) -> bool
    {
        std::filesystem::path target{args};
        std::filesystem::path path{io->session->user->base / target};
        std::string pstr = path.string();
        if(CreateDirectoryA(pstr.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
        {
            io->type = IO_OP_TYPE::IO_SEND;
            return SendResponse(
                io, 
                FTP_RETURN_CODE::PATHNAME_CREATED, 
                std::format("/{}", std::filesystem::relative(std::filesystem::canonical(path), io->session->user->base).string()));
        }
        
        return SendResponse(io, FTP_RETURN_CODE::FAILED_FILE_OP, "Couldn't create directory.");
    });
}
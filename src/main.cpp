#pragma once

#include "ftp_win.hpp"
#include "ftp_handlers.hpp"
#include "ftp_user.hpp"
#include "ftp_config.hpp"
#include <string>
#include <iostream>
#include <string>
#include <map>
#include <fstream>

void print_usage()
{
    std::cout 
        << "USAGE: ftpserv.exe -c CONF" << std::endl
        << "       ftpserv.exe -cc CONF -cu USER -cp PASS -cd DIR" << std::endl << std::endl
        << "\t    -c CONF\t Loads configuration file from CONF" << std::endl
        << "\t-c[c/u/o/d]\t Functions for creating an user in-place" << std::endl; 
}

DWORD WINAPI ServerCommandThread(LPVOID lpParam);

int main(int argc, char const *argv[])
{    
    std::map<std::string, std::string> params;
    for(int i = 1; i < argc; i++)
    {
        std::string str{ argv[i] };
        if(str.starts_with('-') && i < (argc - 1))
        {
            params.emplace(str, std::string{ argv[i + 1] });
            i++;
        }
    }

    if(params.contains("-cc"))
    {
        ftp_user newusr;
        newusr.user = params["-cu"];
        newusr.hash = GetPasswordHash(params["-cp"]);
        newusr.base = params["-cd"];

        append_user(newusr, params["-cc"]);
        return 0;
    }

    std::string config_path; 
    if(params.contains("-c"))
        config_path = params["-c"];
    else
    {
        std::cerr << "Missing configuration file path\n";
        print_usage();
        return 1;
    }

    config conf = load_config(config_path);
    if(!conf.valid)
    {
        std::cerr << "Invalid configuration file." << std::endl;
        return 1;
    }

    if(conf.port.empty())
        conf.port = "21";

    WSADATA wsaData;
    
    if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return 1;

    struct addrinfo hints, *addr;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if(getaddrinfo(conf.endpoint.c_str(), conf.port.c_str(), &hints, &addr) != 0)
        return 1;

    server_state server;
    server.config_path = config_path;
    if(!CreateServer(server, addr))
    {
        WSACleanup();
        return 1;
    }

    RegisterFTPHandlers();

    for(int i = 0; i < 8; i++)
    {
        CreateThread(NULL, 0, FTPWorkerThread, &server, 0, NULL);
    }

    for(int i = 0; i < 2; i++)
    {
        StartAcceptEx(server);
    }

    server.shutdown_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    CreateThread(NULL, 0, ServerCommandThread, &server, 0, NULL);

    WaitForSingleObject(server.shutdown_event, INFINITE);

    closesocket(server.listener);
    CloseHandle(server.iocp);
    WSACleanup();

    return 0;
}

DWORD WINAPI ServerCommandThread(LPVOID lpParam)
{
    server_state* server = (server_state*)lpParam;

    std::string line, cmd;
    while(true)
    {
        std::getline(std::cin, line);
        std::istringstream ss{line};
        if(ss >> cmd)
        {
            if(cmd == "quit")
            {
                SetEvent(server->shutdown_event);
                std::cout << "Shutting down!" << std::endl;
                break;
            }
            else if(cmd == "adduser")
            {
                ftp_user newusr;
                std::string pass;
                ss >> newusr.user;
                ss >> pass;
                newusr.hash = GetPasswordHash(pass);
                ss.ignore();
                std::getline(ss, newusr.base);

                RegisterFTPUser(newusr);
                append_user(newusr, server->config_path);
                std::cout << "Added new user!" << std::endl;
            }
        }
    }

    return 0;
}
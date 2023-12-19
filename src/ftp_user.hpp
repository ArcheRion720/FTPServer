#pragma once
#include <string>

struct ftp_user
{
    std::string user;
    uintmax_t hash;
    std::string base;
};

void RegisterFTPUser(ftp_user user);
bool GetFTPUser(std::string& username, ftp_user** user);
size_t GetPasswordHash(std::string& pass);
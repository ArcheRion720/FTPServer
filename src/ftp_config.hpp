#pragma once
#include <string>
#include "ftp_user.hpp"

struct config
{
    bool valid;
    std::string endpoint;
    std::string port;
    int users_loaded;
};

config load_config(std::string path);
void append_user(ftp_user user, std::string path);
#include "ftp_user.hpp"
#include <fstream>
#include <sstream>
#include <map>

#include <filesystem>
#include <iostream>

static std::map<std::string, ftp_user> users;

int LoadFTPUsers(std::string& path)
{
    std::ifstream conf(path);
    std::string line;
    int result = 0;

    ftp_user temp;
    while(std::getline(conf, line))
    {
        std::istringstream ss{line};
        if(!(ss >> temp.user >> temp.hash))
            break;

        ss.ignore();
        std::getline(ss, temp.base);

        users.emplace(temp.user, temp);
        result++;
    }

    return result;
}

void RegisterFTPUser(ftp_user user)
{
    users.emplace(user.user, user);
}

bool GetFTPUser(std::string& username, ftp_user** user)
{
    if(users.contains(username))
    {
        *user = &users[username];
        return true;
    }

    return false;
}

size_t GetPasswordHash(std::string& pass)
{
    size_t hash, i;
    for(hash = i = 0; i < pass.length(); ++i)
    {
        hash += pass[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    } 

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}
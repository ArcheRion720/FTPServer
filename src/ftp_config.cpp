#include "ftp_config.hpp"
#include "ftp_user.hpp"
#include <string>
#include <fstream>
#include <sstream>
#include <map>

#include <filesystem>
#include <iostream>

config load_config(std::string path)
{
    config result;
    result.valid = false;

    std::ifstream conf(path);
    std::string line;

    char mode;
    ftp_user temp;
    while(std::getline(conf, line))
    {
        std::istringstream ss{line};
        ss >> mode;
        switch(mode)
        {
            case 'b':
            {
                ss.ignore();
                std::getline(ss, result.endpoint);
                continue;
            }
            case 'p':
            {
                ss.ignore();
                std::getline(ss, result.port);
                continue;
            }
            case 'u':
            {
                if(!(ss >> temp.user >> temp.hash))
                {
                    std::cerr << "Invalid user entry in config\n";
                    continue;
                }

                ss.ignore();
                std::getline(ss, temp.base);

                RegisterFTPUser(temp);
                result.users_loaded++;
            }
        }
    }

    if(!result.endpoint.empty() && result.users_loaded > 0)
        result.valid = true;

    return result;
}

void append_user(ftp_user user, std::string path)
{
    std::ofstream of;
    of.open(path, std::ios_base::app);
    of << std::format("u {} {} {}",
            user.user, user.hash, user.base) 
        << std::endl;
}

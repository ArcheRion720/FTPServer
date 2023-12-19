#pragma once

#include "ftp_win.hpp"
#include <functional>
#include <vector>

typedef std::function<bool(overlapped_io*, int, std::string&)> ftp_handler;

bool HandleIncomingMessage(overlapped_io* io, int bytes);
// bool HandleOutgoingMessage(overlapped_io* io, int bytes);
void RegisterFTPHandler(std::string command, ftp_handler handler);
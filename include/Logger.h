// Copyright (c) 2019-present Anonymous275.
// BeamMP Launcher code is not in the public domain and is not free software.
// One must be granted explicit permission by the copyright holder in order to modify or distribute any part of the source or binaries.
// Anything else is prohibited. Modified works may not be published and have be upstreamed to the official repository.
///
/// Created by Anonymous275 on 4/2/2020.
///
#pragma once
#include <iostream>
#include <string>
void InitLog();
void except(const std::string& toPrint);
void fatal(const std::string& toPrint);
void debug(const std::string& toPrint);
void error(const std::string& toPrint);
void info(const std::string& toPrint);
void warn(const std::string& toPrint);

void except(const std::wstring& toPrint);
void fatal(const std::wstring& toPrint);
void debug(const std::wstring& toPrint);
void error(const std::wstring& toPrint);
void info(const std::wstring& toPrint);
void warn(const std::wstring& toPrint);
std::string getDate();

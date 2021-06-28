#include "stdafx.h"
struct IUnknown;
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_ERRORS
#pragma warning(disable: 4996)
#include <iostream>
#include <string>
#include <Windows.h>
#include <atlutil.h>
#include <sstream>
#include <iomanip>
#include <locale>
#include <codecvt>
#include <chrono>
#include <stdlib.h>
#include <stdio.h>
#include "Auth/Networking/sha1.hh"
#include "Auth/Networking/WinHttpClient.h"
#include "Auth/Networking/Web2.0.h"
int menu_version = 0;
#define AUTH_URL L"https://sinister.menu/community/auth/index.php"
std::string ws_to_s(const std::wstring&);

std::string get_hwid();

//int is_authed(std::string & username, std::string & password);

std::string url_encode(const std::string &value) {
	std::ostringstream escaped;
	escaped.fill('0');
	escaped << std::hex;

	for (std::string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
		std::string::value_type c = (*i);

		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			escaped << c;
			continue;
		}

		escaped << std::uppercase;
		escaped << '%' << std::setw(2) << int((unsigned char)c);
		escaped << std::nouppercase;
	}

	return escaped.str();
}

namespace HWID {
	void get_processor_infos(std::string &buffer) {
		SYSTEM_INFO sys_info;
		GetSystemInfo(&sys_info);

		buffer += std::to_string(sys_info.wProcessorArchitecture);
		buffer += std::to_string(sys_info.wProcessorLevel);
		buffer += std::to_string(sys_info.wProcessorRevision);
		buffer += std::to_string(sys_info.dwNumberOfProcessors);
	}

	void get_total_memory(std::string &buffer) {
		MEMORYSTATUSEX statex;
		statex.dwLength = sizeof(statex);
		GlobalMemoryStatusEx(&statex);
		buffer += std::to_string(statex.ullTotalPhys);
	}

	void get_computer_name(std::string &buffer) {
		char tmp[MAX_COMPUTERNAME_LENGTH + 1] = {};
		DWORD size = sizeof(tmp);
		GetComputerNameA(tmp, &size);
		buffer += tmp;
	}

	void get_uuid(std::string &buffer) {
		char uuid[128];
		DWORD size = sizeof uuid;

		if (RegGetValueA(
			HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Microsoft\\Cryptography",
			"MachineGuid",
			RRF_RT_REG_SZ,
			nullptr,
			&uuid,
			&size
		) == ERROR_SUCCESS) {
			buffer += uuid;
		}

	}

	void get_motherboard(std::string &buffer) {
		char manufacturer[64];
		DWORD manufacturer_size = sizeof manufacturer;

		if (RegGetValueA(
			HKEY_LOCAL_MACHINE,
			"HARDWARE\\DESCRIPTION\\System\\BIOS",
			"BaseBoardManufacturer",
			RRF_RT_REG_SZ,
			nullptr,
			&manufacturer,
			&manufacturer_size
		) == ERROR_SUCCESS) {
			buffer += manufacturer;
		}

		char product[64];
		DWORD product_size = sizeof product;

		if (RegGetValueA(
			HKEY_LOCAL_MACHINE,
			"HARDWARE\\DESCRIPTION\\System\\BIOS",
			"BaseBoardProduct",
			RRF_RT_REG_SZ,
			nullptr,
			&product,
			&product_size
		) == ERROR_SUCCESS) {
			buffer += product;
		}
	}

	void get_hw_profile_info(std::string &buffer) {
		HW_PROFILE_INFOA hwProfileInfo;
		GetCurrentHwProfileA(&hwProfileInfo);
		buffer += hwProfileInfo.szHwProfileGuid;
	}

	void get_volume_serial(std::string &buffer) {
		char volumename[MAX_PATH + 1] = { 0 };
		char filesystemname[MAX_PATH + 1] = { 0 };
		DWORD serialnumber = 0, maxcomponentlen = 0, filesystemflags = 0;
		GetVolumeInformationA("C:\\", volumename, ARRAYSIZE(volumename), &serialnumber, &maxcomponentlen, &filesystemflags, filesystemname, ARRAYSIZE(filesystemname));
		buffer += std::to_string(serialnumber);
		buffer += std::to_string(maxcomponentlen);
		buffer += std::to_string(filesystemflags);
		buffer += filesystemname;
	}
}

std::string get_hwid() {
	std::string buffer;

	HWID::get_total_memory(buffer);
	buffer += "\n";
	HWID::get_computer_name(buffer);
	buffer += "\n";
	HWID::get_uuid(buffer);
	buffer += "\n";
	HWID::get_hw_profile_info(buffer);
	buffer += "\n";
	HWID::get_volume_serial(buffer);
	buffer += "\n";
	HWID::get_processor_infos(buffer);
	buffer += "\n";
	HWID::get_motherboard(buffer);

	return buffer;
}

int Auth::is_authed(std::string &username, std::string &password) {
	std::string secret = std::to_string(GetTickCount());

	net::requests request(const_cast<wchar_t*>(L"Mozilla/5.0 (Windows NT; Win64;) Sinister (like Gecko)"), true);
	size_t length = wcslen(AUTH_URL) + 1;
	wchar_t *auth_url = new wchar_t[length];
	wcsncpy_s(auth_url, length, AUTH_URL, length);

	std::wstring answer_wide = request.Post(
		false,
		auth_url,
		"username=%s&password=%s&hwid=%s",
		url_encode(username).c_str(),
		url_encode(password).c_str(),
		url_encode(get_hwid()).c_str()
		//url_encode(secret).c_str()
	);

	int delimiter_location = answer_wide.find(L"\n");

	std::wstring server_hash = answer_wide.substr(0, delimiter_location);
	std::string client_hash = sw::sha1::calculate(secret + "nocraccpls");

	std::wstring answer = answer_wide.substr(delimiter_location + 1, answer_wide.length() - delimiter_location);


	if (answer == L"Access Granted") {
		Log::Msg("Access Granted");
		menu_version = 7;
		return 7; // VIP
	}
	else if (answer == L"Bad HWID") {
		Log::Fatal("Diffrent HWID - Contact Staff");
		exit(0);
	}
	else if (answer == L"Bad Login") {
		Log::Fatal("Bad Login - Check Pass/User");
		exit(0);
	}
	else if (answer == L"Not Authed") {
		Log::Fatal("No Menu");
		menu_version = 0;
		exit(0);
	}
	else
	{
		Log::Fatal("KYS");
		exit(0);
	}
}


std::wstring s2ws(const std::string& str) {
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;
	return converterX.from_bytes(str);
}

std::string ws_to_s(const std::wstring & s)
{
	const wchar_t * cs = s.c_str();
	const size_t wn = std::wcsrtombs(NULL, &cs, 0, NULL);

	std::vector<char> buf(wn + 1);
	const size_t wn_again = std::wcsrtombs(buf.data(), &cs, wn + 1, NULL);

	return std::string(buf.data(), wn);
}
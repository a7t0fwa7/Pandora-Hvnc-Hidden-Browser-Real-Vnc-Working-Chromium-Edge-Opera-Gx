

#include "HVNC.h"



int main(int argc, char* argv[])
{
    if (argc == 1) {
        printf("HVNC PoC \n");
        printf("wazehell @safe_buffer \n");
        printf("Using : %s <executable_path> \n", argv[0]);
        return 1;
    }


    HDESK HDeskTop = NULL;
    HDESK CHDeskTop = NULL;
    DWORD CurrentThread = GetCurrentThreadId();
    CHAR explorer_path[MAX_PATH];
    ExpandEnvironmentStringsA("%windir%\\explorer.exe", explorer_path, MAX_PATH - 1);

    CHDeskTop = GetThreadDesktop(CurrentThread);
    if (!CHDeskTop)
    {
        PrintError((LPTSTR)"GetThreadDesktop");
        return 1;
    }
    printf("[*] Current HDESK %p \n", CHDeskTop);

    HDeskTop = CreateDesktopA(DesktopName, NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!HDeskTop)
    {
        PrintError((LPTSTR)"CreateDesktopA");
        HDeskTop = OpenDesktopA(DesktopName, NULL, FALSE, GENERIC_ALL);
        if (!HDeskTop)
        {
            PrintError((LPTSTR)"OpenDesktopA");
            return 1;
        }
    }

    printf("[*] New HDESK %p , %s \n", HDeskTop, DesktopName);

    if (!SetThreadDesktop(HDeskTop))
    {
        PrintError((LPTSTR)"SetThreadDesktop");
    }

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = (LPTSTR)DesktopName;
    if (!CreateProcessA(explorer_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        PrintError((LPTSTR)"CreateProcessA");
    }

    printf("[*] Started Explorer Process at %s \n", si.lpDesktop);

    if (!SwitchDesktop(HDeskTop))
    {
        PrintError((LPTSTR)"SwitchDesktop");
    }
    printf("[*] Desktop Switched to %p \n", HDeskTop);

    STARTUPINFOA sic = { 0 };
    PROCESS_INFORMATION pic = { 0 };
    memset(&pic, 0, sizeof(pic));
    memset(&sic, 0, sizeof(sic));
    sic.cb = sizeof(sic);
    sic.lpDesktop = (LPTSTR)DesktopName;
    if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, 0, NULL, NULL, &sic, &pic)) {
        PrintError((LPTSTR)"CreateProcessA");
    }
    printf("[*] Started Calc at %s \n", si.lpDesktop);


    printf("[*] Return to orignal Desktop \n");
    if (!SetThreadDesktop(CHDeskTop))
    {
        PrintError((LPTSTR)"SetThreadDesktop");
    }
    if (!SwitchDesktop(CHDeskTop))
    {
        PrintError((LPTSTR)"SwitchDesktop");
    }

    if (!CloseDesktop(HDeskTop))
    {
        PrintError((LPTSTR)"CloseDesktop");
    }
    printf("[*] Closed HDESK %p \n", HDeskTop);

}

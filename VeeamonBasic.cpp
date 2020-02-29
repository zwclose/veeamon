#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <psapi.h>
#include <stdio.h>

enum NameEntryType
{
    ProcessEntry,
    MonitoredEntry,
    FileEntry
};

enum RequestFlags : BYTE
{
    RF_CallPreHandler = 0x1,
    RF_CallPostHandler = 0x2,
    RF_PassDown = 0x10,
    RF_Wait = 0x20,
    RF_DenyAccess = 0x40,
    RF_CompleteRequest = 0x80,
};

struct CtrlBlock
{
    BYTE ProcessIndex;
    BYTE FolderIndex;
    WORD FileIndex : 10;
    WORD MajorFunction : 6;
};

struct SharedBufferEntry
{
    //header
    DWORD Flags;
    union
    {
        CtrlBlock Ctrl;
        DWORD d1;
    };

    //body
    DWORD d2;
    DWORD d3;

    DWORD d4;
    DWORD d5;
    DWORD d6;
    DWORD d7;
};

struct SharedBufferDescriptor
{
    DWORD FolderIndex;
    DWORD SharedBufferLength;
    DWORD SharedBufferPtr;
    DWORD Unk;
};

SharedBufferDescriptor SharedBufDesc;

#define IOCTL_START_FOLDER_MONITORING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222400
#define IOCTL_STOP_FOLDER_MONITORING  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222404
#define IOCTL_UNWAIT_REQUEST          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x920, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222480
#define IOCTL_SET_STREAM_FLAGS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222440

BOOL CtlDestroyFolder(HANDLE hDevice, DWORD FolderIndex)
{
    DWORD BytesReturned;

    BOOL r = DeviceIoControl(hDevice, IOCTL_STOP_FOLDER_MONITORING, &FolderIndex, sizeof(FolderIndex), 0, 0, &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("DestroyFolder failed\n");
    }
    return r;
}

BOOL CtlCreateMonitoredFolder(
    HANDLE hDevice,
    PCWCHAR FolderPathName,
    PHANDLE SharedBufSemaphore,
    PHANDLE NewEntrySemaphore
)
{
    DWORD BytesReturned;

    struct MonitoredFolder
    {
        HANDLE SharedBufSemaphore;
        DWORD d1;
        HANDLE NewEntrySemaphore;
        DWORD d2;
        DWORD f1;  //+0x10
        DWORD SharedBufferEntriesCount; //+0x14
        DWORD PathLength; //+0x18
        WCHAR PathName[0x80]; //+0x1C
    };

    MonitoredFolder Folder = { };
    //const wchar_t *pFolderPath = L"\\Device\\HardDiskVolume1\\TMP\\";

    *SharedBufSemaphore = *NewEntrySemaphore = nullptr;
    // Add protected folder
    Folder.SharedBufSemaphore = CreateSemaphoreW(nullptr, 0, 10000, nullptr);
    Folder.NewEntrySemaphore = CreateSemaphoreW(nullptr, 1, 10000, nullptr);
    Folder.f1 = 0x20;
    Folder.SharedBufferEntriesCount = 0x200;
    Folder.PathLength = wcslen(FolderPathName) * sizeof(FolderPathName[0]);
    wcscpy(Folder.PathName, FolderPathName);
    BOOL r = DeviceIoControl(hDevice, IOCTL_START_FOLDER_MONITORING, &Folder, sizeof(Folder), &SharedBufDesc, sizeof(SharedBufDesc), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("CreateFolder failed\n");
    }
    else
    {
        *SharedBufSemaphore = Folder.SharedBufSemaphore;
        *NewEntrySemaphore = Folder.NewEntrySemaphore;
        if (BytesReturned != sizeof(SharedBufDesc))
        {
            printf("Bad sizeof shared buffer\n");
            r = FALSE;
        }
    }
    return r;
}

BOOL CtlUnwaitRequest(
    HANDLE hDevice,
    CtrlBlock* Ctrl,
    WORD SharedBufferEntryIndex,
    RequestFlags RFlags
)
{
    struct UnwaitDescriptor
    {
        CtrlBlock Ctrl;

        DWORD SharedBufferEntryIndex;
        RequestFlags RFlags;
        BYTE  IsStatusPresent;
        BYTE  IsUserModeBuffPresent;
        BYTE  SetSomeFlag;
        DWORD Status;
        DWORD Information;
        PVOID UserBuff;
        DWORD d6;
        DWORD UserBuffLength;
    };

    DWORD BytesReturned;
    UnwaitDescriptor Unwait = { 0, };

    Unwait.Ctrl.FolderIndex = Ctrl->FolderIndex;
    Unwait.Ctrl.MajorFunction = Ctrl->MajorFunction;
    Unwait.Ctrl.FileIndex = Ctrl->FileIndex;
    Unwait.SharedBufferEntryIndex = SharedBufferEntryIndex;
    Unwait.RFlags = RFlags;

    Unwait.IsUserModeBuffPresent = 0;

    // Uncomment the code below to crash the OS.
    // VeeamFSR doesn't handle this parameter correctly. Setting IsUserModeBuffPresent to true 
    // leads to double free in the completion rountine.
    //Unwait.UserBuff = (PVOID)"aaaabbbb";
    //Unwait.UserBuffLength = 8;
    //Unwait.IsUserModeBuffPresent = 1;


    BOOL r = DeviceIoControl(hDevice, IOCTL_UNWAIT_REQUEST, &Unwait, sizeof(Unwait), 0, 0, &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("UnwaitRequest failed\n");
    }
    return r;
}

BOOL CtlUnwaitRequest(
    HANDLE hDevice,
    CtrlBlock* Ctrl,
    WORD SharedAreaEntryIndex
)
{
    return CtlUnwaitRequest(hDevice, Ctrl, SharedAreaEntryIndex, RF_PassDown);
}

DWORD GetProcessImageFileNameByPid(DWORD Pid, PWCHAR pBuf, DWORD Length)
{
    DWORD r = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (hProcess == NULL)
    {
        printf("OpenProcess failed with %d for pid %d\n", GetLastError(), Pid);
    }
    else
    {
        r = GetProcessImageFileNameW(hProcess, pBuf, Length);
        if (r == 0)
        {
            printf("GetProcessImageFileNameW failed: %d\n", GetLastError());
        }
        CloseHandle(hProcess);
    }

    return r;
}

DWORD FileMapping[0x80];
DWORD ProcessMapping[0x80];

VOID PrintEntryInfo(const CHAR* pOpName, SharedBufferEntry IOEntryBuffer[], SharedBufferEntry* pEntry)
{
    WCHAR ProcessName[MAX_PATH];
    DWORD ProcessIndex = ProcessMapping[pEntry->Ctrl.ProcessIndex];
    DWORD Pid = IOEntryBuffer[ProcessIndex].d6;
    DWORD ProcessNameLength = GetProcessImageFileNameByPid(Pid, ProcessName, MAX_PATH);
    DWORD NameIndex = FileMapping[pEntry->Ctrl.FileIndex];
    printf("%s for %ls by process %d (%ls)\n", pOpName, (PWSTR)IOEntryBuffer[NameIndex].d6, Pid, ProcessNameLength == 0 ? L"null" : ProcessName);
}

VOID PrintBuffer(PBYTE pBuffer, DWORD Length)
{
    for (int i = 0; i < 17; i++)
    {
        if ((i & 7) == 0)
        {
            printf("\n");
        }
        if (IsCharAlphaNumericA(pBuffer[i]) == TRUE)
        {
            printf(" %c ", pBuffer[i]);
        }
        else
        {
            printf("%02x ", pBuffer[i]);
        }
    }
    printf("\n");
}

int wmain(int arc, wchar_t** argv)
{
    if (arc != 2)
    {
        printf("Usage: veeamon NativePathToFolder\n");
        return -1;
    }

    HANDLE hDevice = CreateFileW(L"\\\\.\\VeeamFSR", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileW: %d\n", GetLastError());
        return -1;
    }

    HANDLE SharedBufSemaphore;
    HANDLE NewEntrySemaphore;
    WORD CurrEntry = 0;

    PCWCHAR Folder = argv[1];
    if (CtlCreateMonitoredFolder(
        hDevice,
        Folder,
        &SharedBufSemaphore,
        &NewEntrySemaphore) == FALSE)
    {
        printf("Failed setting up monitored folder\n");
        return -1;
    }

    printf("Set up monitor on %ls\n", Folder);
    printf("FolderIndex: 0x%x\n", SharedBufDesc.FolderIndex);
    printf("Shared buffer: %p\n", (PVOID)SharedBufDesc.SharedBufferPtr);
    printf("Shared buffer length: 0x%x\n", SharedBufDesc.SharedBufferLength);
    printf("Uknown: 0x%x\n", SharedBufDesc.Unk);
    printf("\nStarting IO loop\n");

    SharedBufferEntry* IOEntryBuffer = (SharedBufferEntry*)SharedBufDesc.SharedBufferPtr;
    SharedBufferEntry* IOEntry;

    for (;;)
    {
        LONG l;

        ReleaseSemaphore(NewEntrySemaphore, 1, &l);
        WaitForSingleObject(SharedBufSemaphore, INFINITE);

        printf("Entry #%d\n", CurrEntry);

        IOEntry = &IOEntryBuffer[CurrEntry];
        switch (IOEntry->Ctrl.MajorFunction)
        {
        //
        // IRP_MJ_XXX and FastIo handlers
        //
        case 0x0: //IRP_MJ_CREATE
        case 0x33: //Fast _IRP_MJ_CREATE
        {
            PrintEntryInfo("IRP_MJ_CREATE", IOEntryBuffer, IOEntry);
            CtlUnwaitRequest(hDevice, &IOEntry->Ctrl, CurrEntry, RF_PassDown);

            break;
        }
        default:
        {
            CHAR OpName[40]{};
            sprintf_s(OpName, 40, "IRP_MJ_%d", IOEntry->Ctrl.MajorFunction);
            PrintEntryInfo(OpName, IOEntryBuffer, &IOEntryBuffer[CurrEntry]);

            break;
        }


        //
        // Special entry handlers
        //
        case 0x37: //Name entry
        {
            printf("\tADD\n");

            switch (IOEntry->d2)
            {
            case ProcessEntry:
                printf("\tprocess: %d\n", IOEntry->d6);
                ProcessMapping[IOEntry->d3] = CurrEntry;
                break;
            case FileEntry:
                //.d4 == length
                printf("\tfile: %ls\n", (PWSTR)IOEntry->d6);
                FileMapping[IOEntry->d3] = CurrEntry;
                break;
            case MonitoredEntry:
                //.d4 == length
                printf("\tmonitored dir: %ls\n", (PWSTR)IOEntry->d6);
                break;
            }

            break;
        }
        case 0x38:
        {
            printf("\tDELETION\n");
            switch (IOEntry->d2)
            {
            case ProcessEntry:
                printf("\tprocess\n");
                break;
            case FileEntry:
                printf("\tfile\n");
                break;
            case MonitoredEntry:
                printf("\tmonitored dir\n");
                break;
            }
            printf("\tindex: %d\n", IOEntry->d2);

            break;
        }
        case 0x39:
        {
            printf("\tCOMPLETION of IRP_MJ_%d, index = %d, status = 0x%x, information: 0x%x\n",
                IOEntry->d2,
                IOEntry->d3,
                IOEntry->d4,
                IOEntry->d5);

            break;
        }
        case 0x3A:
        {
            printf("\tWRITE-related entry\n");
            break;
        }
        }

        printf("\t0x%.8x 0x%.8x  0x%.8x 0x%.8x\n", IOEntry->Flags, IOEntry->d1, IOEntry->d2, IOEntry->d3);
        printf("\t0x%.8x 0x%.8x  0x%.8x 0x%.8x\n", IOEntry->d4, IOEntry->d5, IOEntry->d6, IOEntry->d7);

        CurrEntry++;
        if (CurrEntry >= 0x200)
        {
            break;
        }
    }

    CtlDestroyFolder(hDevice, 0);
    CloseHandle(hDevice);

    printf("Press any key...\n");
    getchar();

    return 0;
}

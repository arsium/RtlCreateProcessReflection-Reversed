# RtlCreateProcessReflection-Reversed

95% reverse RtlCreateProcessReflection, which serves to create some "fork" processes in Windows.

## Flow

`RtlCreateProcessReflection->[RtlpProcessReflectionStartup]->Return to RtlCreateProcessReflection->RtlpCreateUserThreadEx

[RtlpProcessReflectionStartup->RtlCloneUserProcess->RtlpCreateUserProcess->NtCreateUserProcess]`

## RtlCreateProcessReflection

```c
__int64 __fastcall RtlCreateProcessReflection(
        HANDLE ProcessHandle,
        ULONG Flags,
        PVOID StartRoutine,
        PVOID StartContext,
        HANDLE EventHandle,
        PPROCESS_REFLECTION_INFORMATION ReflectionInformation)
{
  int status_allocate; // ebx
  PVOID BaseAddress_loc; // rcx
  SIZE_T RegionSize_Loc; // rax
  PVOID base_address_buffer; // rax
  _OWORD *BaseAddress_loc2; // rax
  _OWORD *BaseAddress_MapView_loc; // rcx
  HANDLE EventHandle_3; // rcx
  int status_dup; // eax
  int InitialState; // [rsp+28h] [rbp-99h]
  int InitialState_2; // [rsp+28h] [rbp-99h]
  PVOID StartAddress; // [rsp+38h] [rbp-89h]
  PVOID BaseAddress; // [rsp+68h] [rbp-59h] BYREF
  PVOID BaseAddress_MapView; // [rsp+70h] [rbp-51h] BYREF
  SIZE_T RegionSize; // [rsp+78h] [rbp-49h] BYREF
  HANDLE SourceHandle; // [rsp+80h] [rbp-41h] BYREF
  ULONG ProcessInformationLength[2]; // [rsp+88h] [rbp-39h] BYREF
  _UNICODE_STRING *ProcessInformation_ImageName; // [rsp+90h] [rbp-31h] BYREF
  PVOID BaseAddress_MapView_2; // [rsp+98h] [rbp-29h] BYREF
  HANDLE SectionHandle; // [rsp+A0h] [rbp-21h] BYREF
  HANDLE EventHandle_1; // [rsp+A8h] [rbp-19h] BYREF
  struct _CLIENT_ID Handle; // [rsp+B0h] [rbp-11h] BYREF
  SIZE_T MaximumSize; // [rsp+C0h] [rbp-1h] BYREF
  HANDLE ArrayHandle[2]; // [rsp+C8h] [rbp+7h] BYREF
  LARGE_INTEGER SystemTime; // [rsp+D8h] [rbp+17h] BYREF
  LARGE_INTEGER SystemTime2; // [rsp+E0h] [rbp+1Fh] BYREF

  *(_QWORD *)ProcessInformationLength = 4096;
  Handle.UniqueProcess = 0;
  BaseAddress_MapView = 0;
  ProcessInformation_ImageName = 0;
  BaseAddress = 0;
  SectionHandle = 0;
  MaximumSize = 0;
  Handle.UniqueThread = 0;
  BaseAddress_MapView_2 = 0;
  EventHandle_1 = 0;
  SourceHandle = 0;
  ZwQuerySystemTime(&SystemTime);
  if ( (Flags & 0xFFFFFFE1) != 0 )
    return 3221225712LL;
  if ( (Flags & 8) != 0 && StartRoutine )
    return 3221225715LL;
  if ( ReflectionInformation )
  {
    *(_OWORD *)&ReflectionInformation->ReflectionProcessHandle = 0;
    ReflectionInformation->ReflectionClientId = 0;
  }
  status_allocate = ZwAllocateVirtualMemory(-1, &ProcessInformation_ImageName, 0, ProcessInformationLength, 12288, 4);
  if ( status_allocate < 0 )
  {
    ProcessInformation_ImageName = 0;
    goto LABEL_41;
  }
  NtQueryInformationProcess(
    (HANDLE)0xFFFFFFFFFFFFFFFFLL,
    ProcessImageFileName,
    ProcessInformation_ImageName,
    ProcessInformationLength[0],
    ProcessInformationLength);
  *(_QWORD *)ProcessInformationLength = 4096;
  ZwFreeVirtualMemory(-1, &ProcessInformation_ImageName, ProcessInformationLength, 0x8000);
  RegionSize = 88;
  status_allocate = ZwAllocateVirtualMemory(-1, &BaseAddress, 0, &RegionSize, 12288, 4);
  if ( status_allocate < 0 )
  {
    BaseAddress = 0;
    goto LABEL_41;
  }
  BaseAddress_loc = BaseAddress;
  RegionSize_Loc = RegionSize;
  *((_QWORD *)BaseAddress + 3) = StartContext;
  *((_QWORD *)BaseAddress_loc + 2) = StartRoutine;
  *(_QWORD *)BaseAddress_loc = RegionSize_Loc;
  *((_DWORD *)BaseAddress_loc + 2) = Flags;
  *((_QWORD *)BaseAddress_loc + 6) = EventHandle;
  if ( ProcessHandle == (HANDLE)-1LL )
  {
    *((_DWORD *)BaseAddress_loc + 2) = Flags | 0x10;
    status_allocate = RtlpProcessReflectionStartup(BaseAddress);
    if ( status_allocate >= 0 && ReflectionInformation )
    {
      ReflectionInformation->ReflectionProcessHandle = (HANDLE)*((_QWORD *)BaseAddress + 7);
      ReflectionInformation->ReflectionThreadHandle = (HANDLE)*((_QWORD *)BaseAddress + 8);
      ReflectionInformation->ReflectionClientId.UniqueProcess = (HANDLE)*((_QWORD *)BaseAddress + 9);
      base_address_buffer = BaseAddress;
LABEL_40:
      ReflectionInformation->ReflectionClientId.UniqueThread = (HANDLE)*((_QWORD *)base_address_buffer + 10);
      goto LABEL_41;
    }
    goto LABEL_41;
  }
  MaximumSize = RegionSize;
  status_allocate = NtCreateSection(&SectionHandle, 6, 0, &MaximumSize, 4, 0x8000000, 0);
  if ( status_allocate < 0 )
    goto LABEL_41;
  Handle.UniqueThread = (HANDLE)RegionSize;
  status_allocate = ZwMapViewOfSection(
                      SectionHandle,
                      ProcessHandle,
                      &BaseAddress_MapView_2,
                      0,
                      RegionSize,
                      0,
                      &Handle.UniqueThread,
                      2,
                      0,
                      4);
  if ( status_allocate >= 0 )
  {
    status_allocate = ZwMapViewOfSection(
                        SectionHandle,
                        -1,
                        &BaseAddress_MapView,
                        0,
                        RegionSize,
                        0,
                        &Handle.UniqueThread,
                        2,
                        0,
                        4);
    if ( status_allocate < 0 )
    {
      BaseAddress_MapView = 0;
      goto LABEL_41;
    }
    if ( !ReflectionInformation
      || (LOBYTE(InitialState) = 0,
          status_allocate = ZwCreateEvent(&EventHandle_1, 2031619, 0, 0, InitialState),
          status_allocate >= 0)
      && (LOBYTE(InitialState_2) = 0,
          status_allocate = ZwCreateEvent(&SourceHandle, 2031619, 0, 0, InitialState_2),
          status_allocate >= 0)
      && (status_allocate = ZwDuplicateObject(-1, EventHandle_1, ProcessHandle, (char *)BaseAddress + 32, 2031619, 0, 2),
          status_allocate >= 0)
      && (status_allocate = ZwDuplicateObject(-1, SourceHandle, ProcessHandle, (char *)BaseAddress + 40, 2031619, 0, 2),
          status_allocate >= 0)
      && (!EventHandle
       || (status_allocate = ZwDuplicateObject(-1, EventHandle, ProcessHandle, (char *)BaseAddress + 48, 2031619, 0, 2),
           status_allocate >= 0)) )
    {
      BaseAddress_loc2 = BaseAddress;
      BaseAddress_MapView_loc = BaseAddress_MapView;
      *(_OWORD *)BaseAddress_MapView = *(_OWORD *)BaseAddress;
      BaseAddress_MapView_loc[1] = BaseAddress_loc2[1];
      BaseAddress_MapView_loc[2] = BaseAddress_loc2[2];
      BaseAddress_MapView_loc[3] = BaseAddress_loc2[3];
      BaseAddress_MapView_loc[4] = BaseAddress_loc2[4];
      *((_QWORD *)BaseAddress_MapView_loc + 10) = *((_QWORD *)BaseAddress_loc2 + 10);
      status_allocate = RtlpCreateUserThreadEx(
                          ProcessHandle,
                          0,
                          2u,
                          0,
                          0,
                          0,
                          StartAddress,
                          RtlpProcessReflectionStartup,
                          (PHANDLE)BaseAddress_MapView_2,
                          &Handle);
      if ( status_allocate >= 0 )
      {
        if ( ReflectionInformation )
        {
          ArrayHandle[0] = Handle.UniqueProcess;
          ArrayHandle[1] = EventHandle_1;
          if ( ((NTSTATUS (__fastcall *)(ULONG, HANDLE[], WAIT_TYPE, BOOLEAN, PLARGE_INTEGER))NtWaitForMultipleObjects)(
                 2u,
                 ArrayHandle,
                 WaitAny,
                 0,
                 0) == 1 )
          {
            if ( *((_QWORD *)BaseAddress_MapView + 7) )
            {
              if ( (int)ZwDuplicateObject(
                          ProcessHandle,
                          *((_QWORD *)BaseAddress_MapView + 7),
                          -1,
                          ReflectionInformation,
                          0x1FFFFF,
                          0,
                          2) >= 0 )
              {
                status_dup = ZwDuplicateObject(
                               ProcessHandle,
                               *((_QWORD *)BaseAddress_MapView + 8),
                               -1,
                               &ReflectionInformation->ReflectionThreadHandle,
                               0x1FFFFF,
                               0,
                               2);
                EventHandle_3 = SourceHandle;
                if ( status_dup >= 0 )
                {
                  status_allocate = ZwSetEvent(SourceHandle, 0);
                  ReflectionInformation->ReflectionClientId.UniqueProcess = (HANDLE)*((_QWORD *)BaseAddress_MapView + 9);
                  base_address_buffer = BaseAddress_MapView;
                  goto LABEL_40;
                }
              }
              else
              {
                EventHandle_3 = SourceHandle;
              }
              status_allocate = ZwSetEvent(EventHandle_3, 0);
              goto LABEL_41;
            }
            NtWaitForSingleObject(Handle.UniqueProcess, 0, 0);
          }
          status_allocate = -1073741823;
        }
      }
    }
LABEL_41:
    if ( BaseAddress_MapView_2 )
      NtUnmapViewOfSection(ProcessHandle, BaseAddress_MapView_2);
    goto LABEL_43;
  }
  BaseAddress_MapView_2 = 0;
LABEL_43:
  if ( BaseAddress_MapView )
    NtUnmapViewOfSection(-1, BaseAddress_MapView);
  if ( SectionHandle )
    NtClose(SectionHandle);
  if ( BaseAddress )
    ZwFreeVirtualMemory(-1, &BaseAddress, &RegionSize, 0x8000);
  if ( EventHandle_1 )
    NtClose(EventHandle_1);
  if ( SourceHandle )
    NtClose(SourceHandle);
  if ( Handle.UniqueProcess )
    NtClose(Handle.UniqueProcess);
  ZwQuerySystemTime(&SystemTime2);
  return (unsigned int)status_allocate;
}
```

## RtlpProcessReflectionStartup

```c
__int64 __fastcall RtlpProcessReflectionStartup(PVOID Buffer)
{
  int ntstatus_syscall; // r14d
  _OWORD *BaseAddress_loc; // rax
  int ProcessFlags; // ecx
  int ntstatus_cloned; // eax
  HANDLE ProcessHandle; // r8
  HANDLE handle_event_loc; // rdx
  int ntstatus_syscall_loc; // eax
  __int64 ProcessHandle_loc; // rcx
  __int64 SourceHandle_unknown; // rdx
  void *unknown; // r15
  HANDLE ProcessHandle_1; // rbx
  HANDLE ThreadHandle; // rdi
  __int64 EventHandle_1; // rcx
  void *Handle_1; // rsi
  void (__fastcall *unknown_2)(_QWORD); // rax
  __int64 unknown_1; // rcx
  int InitialState; // [rsp+20h] [rbp-89h]
  SIZE_T RegionSize[2]; // [rsp+40h] [rbp-69h] BYREF
  struct _RTL_USER_PROCESS_INFORMATION OutProcessInformation; // [rsp+50h] [rbp-59h] BYREF
  PVOID BaseAddress; // [rsp+110h] [rbp+67h] BYREF
  HANDLE EventHandle; // [rsp+118h] [rbp+6Fh] BYREF
  HANDLE handle_Waiting_unknown; // [rsp+120h] [rbp+77h] BYREF
  HANDLE Handle; // [rsp+128h] [rbp+7Fh] BYREF

  Handle = 0;
  BaseAddress = 0;
  handle_Waiting_unknown = 0;
  EventHandle = 0;
  ntstatus_syscall = ZwAllocateVirtualMemory(-1, &BaseAddress, 0, Buffer, 12288, 4);// size of 88
                                                // Since   :
                                                //  RegionSize = 88;
                                                //   status_allocate = ZwAllocateVirtualMemory(-1, &BaseAddress, 0, &RegionSize, 12288, 4);
                                                //   if ( status_allocate < 0 )
                                                //   {
                                                //     BaseAddress = 0;
                                                //     goto LABEL_41;
                                                //   }
                                                //   BaseAddress_loc = BaseAddress;
                                                //   RegionSize_Loc = RegionSize;
                                                //   *((_QWORD *)BaseAddress + 3) = StartContext;
                                                //   *((_QWORD *)BaseAddress_loc + 2) = StartRoutine;
                                                //   *(_QWORD *)BaseAddress_loc = RegionSize_Loc;
                                                //   *((_DWORD *)BaseAddress_loc + 2) = Flags;
                                                //   *((_QWORD *)BaseAddress_loc + 6) = EventHandle;
                                                //   if ( ProcessHandle == (HANDLE)-1LL )
                                                //   {
                                                //     *((_DWORD *)BaseAddress_loc + 2) = Flags | 0x10;
                                                //     status_allocate = RtlpProcessReflectionStartup(BaseAddress);
  if ( ntstatus_syscall < 0 )
  {
    *(_OWORD *)((char *)Buffer + 56) = 0;
    *(_OWORD *)((char *)Buffer + 72) = 0;
    goto LABEL_28;
  }
  BaseAddress_loc = BaseAddress;
  *(_OWORD *)BaseAddress = *(_OWORD *)Buffer;
  BaseAddress_loc[1] = *((_OWORD *)Buffer + 1);
  BaseAddress_loc[2] = *((_OWORD *)Buffer + 2);
  BaseAddress_loc[3] = *((_OWORD *)Buffer + 3);
  BaseAddress_loc[4] = *((_OWORD *)Buffer + 4);
  *((_QWORD *)BaseAddress_loc + 10) = *((_QWORD *)Buffer + 10);
  LOBYTE(InitialState) = 0;
  ntstatus_syscall = ZwCreateEvent(&Handle, 2031619, 0, 0, InitialState);
  if ( ntstatus_syscall >= 0 )
  {
    ProcessFlags = *((_DWORD *)Buffer + 2) & 2 | 4;
    if ( (*((_DWORD *)Buffer + 2) & 8) == 0 )
      ProcessFlags = *((_DWORD *)Buffer + 2) & 2;
    ntstatus_cloned = RtlCloneUserProcess(ProcessFlags | 1u, 0, 0, 0, &OutProcessInformation);
    ntstatus_syscall = ntstatus_cloned;
    if ( ntstatus_cloned )
    {
      if ( ntstatus_cloned == 0x129 )
      {
        NtCurrentPeb()->Ldr->ShutdownInProgress = 1;
        ZwSetEvent(EventHandle, 0);
        NtClose(EventHandle);
        if ( handle_Waiting_unknown )
        {
          NtWaitForSingleObject(handle_Waiting_unknown, 0, 0);
          NtClose(handle_Waiting_unknown);
        }
        unknown_2 = (void (__fastcall *)(_QWORD))*((_QWORD *)BaseAddress + 2);
        if ( unknown_2 )
        {
          unknown_2(*((_QWORD *)BaseAddress + 3));
        }
        else if ( (*((_DWORD *)BaseAddress + 2) & 4) == 0 )
        {
          NtSuspendThread((HANDLE)0xFFFFFFFFFFFFFFFELL, 0);
        }
        RegionSize[0] = *(_QWORD *)BaseAddress;
        ntstatus_syscall_loc = ZwFreeVirtualMemory(-1, &BaseAddress, RegionSize, 0x8000);
        ntstatus_syscall = ntstatus_syscall_loc;
        ProcessHandle_loc = -1;
        goto LABEL_8;
      }
      *((_QWORD *)Buffer + 7) = 0;
      *((_QWORD *)Buffer + 8) = 0;
      *((_QWORD *)Buffer + 9) = 0;
      *((_QWORD *)Buffer + 10) = 0;
      unknown_1 = *((_QWORD *)Buffer + 4);
      if ( unknown_1 )
        ZwSetEvent(unknown_1, 0);
    }
    else
    {
      ProcessHandle = OutProcessInformation.ProcessHandle;
      handle_event_loc = Handle;
      *((_QWORD *)Buffer + 8) = OutProcessInformation.ThreadHandle;
      *(CLIENT_ID *)((char *)Buffer + 72) = OutProcessInformation.ClientId;
      *((_QWORD *)Buffer + 7) = ProcessHandle;
      ntstatus_syscall_loc = ZwDuplicateObject(-1, handle_event_loc, ProcessHandle, &EventHandle, 2031619, 0, 2);
      ProcessHandle_loc = (__int64)OutProcessInformation.ProcessHandle;
      ntstatus_syscall = ntstatus_syscall_loc;
      if ( ntstatus_syscall_loc < 0 )
      {
LABEL_8:
        ZwTerminateProcess(ProcessHandle_loc, (unsigned int)ntstatus_syscall_loc);
        goto LABEL_28;
      }
      ntstatus_syscall_loc = NtWriteVirtualMemory(OutProcessInformation.ProcessHandle, &EventHandle, &EventHandle, 8, 0);
      ntstatus_syscall = ntstatus_syscall_loc;
      if ( ntstatus_syscall_loc < 0 )
        goto LABEL_10;
      SourceHandle_unknown = *((_QWORD *)Buffer + 6);
      if ( SourceHandle_unknown )
      {
        ntstatus_syscall_loc = ZwDuplicateObject(
                                 -1,
                                 SourceHandle_unknown,
                                 OutProcessInformation.ProcessHandle,
                                 &handle_Waiting_unknown,
                                 2031619,
                                 0,
                                 2);
        ntstatus_syscall = ntstatus_syscall_loc;
        if ( ntstatus_syscall_loc < 0 )
          goto LABEL_10;
        if ( (*((_DWORD *)Buffer + 2) & 0x10) == 0 )
          NtClose(*((HANDLE *)Buffer + 6));
        ntstatus_syscall_loc = NtWriteVirtualMemory(
                                 OutProcessInformation.ProcessHandle,
                                 &handle_Waiting_unknown,
                                 &handle_Waiting_unknown,
                                 8,
                                 0);
        ntstatus_syscall = ntstatus_syscall_loc;
        if ( ntstatus_syscall_loc < 0 )
        {
LABEL_10:
          ProcessHandle_loc = (__int64)OutProcessInformation.ProcessHandle;
          goto LABEL_8;
        }
      }
      ZwResumeProcess(OutProcessInformation.ProcessHandle);
      NtWaitForSingleObject(Handle, 0, 0);
      unknown = (void *)*((_QWORD *)Buffer + 4);
      if ( unknown )
      {
        ProcessHandle_1 = OutProcessInformation.ProcessHandle;
        ThreadHandle = OutProcessInformation.ThreadHandle;
        EventHandle_1 = *((_QWORD *)Buffer + 4);
        Handle_1 = (void *)*((_QWORD *)Buffer + 5);
        ntstatus_syscall = ZwSetEvent(EventHandle_1, 0);
        NtWaitForSingleObject(Handle_1, 0, 0);
        NtClose(ProcessHandle_1);
        NtClose(ThreadHandle);
        NtClose(unknown);
        NtClose(Handle_1);
      }
    }
  }
LABEL_28:
  if ( Handle )
    NtClose(Handle);
  if ( BaseAddress )
  {
    RegionSize[0] = *(_QWORD *)BaseAddress;
    ZwFreeVirtualMemory(-1, &BaseAddress, RegionSize, 0x8000);
  }
  return (unsigned int)ntstatus_syscall;
}
```

## RtlCloneUserProcess

```c
__int64 __fastcall RtlCloneUserProcess(
        ULONG ProcessFlags,
        PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
        PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
        HANDLE DebugPort,
        PRTL_USER_PROCESS_INFORMATION OutProcessInformation)
{
  int LockState; // esi
  ULONG process_flags_loc; // r14d
  ULONG process_flags_loc_2; // ebp
  ULONG process_flags; // edi
  struct _RTLP_FLS_CONTEXT *fls_context; // rcx
  int ntstatus; // ebx
  struct _RTLP_FLS_CONTEXT *v15; // rcx
  unsigned int ntstatus_proc_create; // eax
  unsigned int ntstatus_1; // ebp
  int ReleaseState; // ebx
  struct _RTLP_FLS_CONTEXT *v19; // rcx
  RTL_USER_PROCESS_EXTENDED_PARAMETERS ProcessExtendedParameters; // [rsp+30h] [rbp-68h] BYREF

  if ( (ProcessFlags & 0xFFFFFFF8) != 0 )
    return 3221225711LL;
  LockState = 2;
  process_flags_loc = ProcessFlags & 1;
  process_flags_loc_2 = 2 * (ProcessFlags & 2);
  process_flags = ProcessFlags & 4;
  if ( (ProcessFlags & 4) == 0 )
  {
    if ( (NtCurrentTeb()->SameTebFlags & 0x1000) != 0 )
      return (unsigned int)-1073741420;
    LdrpDrainWorkQueue(0);
    LdrpAcquireLoaderLock();
    RtlEnterCriticalSection(&LdrpWorkQueueLock);
    RtlpFlsClonePrepare(fls_context);
    RtlEnterCriticalSection(&FastPebLock);
    LdrpLockTlsDelayedReclaimTable();
    RtlAcquireSRWLockExclusive(&RtlpProtectedPoliciesSRWLock);
    LdrForkMrdata(0);
    ntstatus = RtlLockHeapManagerForCloning();
    if ( ntstatus >= 0 )
    {
      RtlAcquireSRWLockExclusive(&RtlCriticalSectionLock);
      RtlAcquireSRWLockExclusive(&LdrpForkActiveLock);
      ntstatus = 0;
      LdrpForkInProgress = 1;
    }
    else
    {
      LdrForkMrdata(2);
      RtlReleaseSRWLockExclusive(&RtlpProtectedPoliciesSRWLock);
      LdrpUnlockTlsDelayedReclaimTable(0);
      RtlLeaveCriticalSection(&FastPebLock);
      RtlpFlsCloneComplete(v15, 0);
      LdrpCompleteProcessCloning(0);
    }
    if ( ntstatus < 0 )
      return (unsigned int)ntstatus;
  }
  ProcessExtendedParameters.JobHandle = 0;
  *(_QWORD *)&ProcessExtendedParameters.Version = 1;
  ProcessExtendedParameters.ParentProcess = 0;
  ProcessExtendedParameters.TokenHandle = 0;
  ProcessExtendedParameters.ProcessSecurityDescriptor = ProcessSecurityDescriptor;
  ProcessExtendedParameters.ThreadSecurityDescriptor = ThreadSecurityDescriptor;
  ProcessExtendedParameters.DebugPort = DebugPort;
  ntstatus_proc_create = RtlpCreateUserProcess(
                           0,
                           0,
                           process_flags_loc_2,
                           process_flags_loc,
                           &ProcessExtendedParameters,
                           OutProcessInformation);
  ntstatus_1 = ntstatus_proc_create;
  if ( !process_flags )
  {
    if ( ntstatus_proc_create == 297 )
    {
      RtlCriticalSectionLock = 1;
      ReleaseState = 1;
      LockState = 1;
      qword_18016C0F0 = (__int64)NtCurrentTeb()->ClientId.UniqueThread;
      dword_18016C0E8 = -2;
      dword_18016C0EC = 1;
      qword_18016C0F8 = 0;
    }
    else
    {
      LdrpForkInProgress = 0;
      ReleaseState = 0;
      RtlReleaseSRWLockExclusive(&LdrpForkActiveLock);
    }
    RtlReleaseSRWLockExclusive(&RtlCriticalSectionLock);
    LdrForkMrdata(LockState);
    if ( LockState == 1 )
      RtlpProtectedPoliciesSRWLock = 1;
    else
      RtlReleaseSRWLockExclusive(&RtlpProtectedPoliciesSRWLock);
    RtlUnlockHeapManagerForCloning(ReleaseState);
    LdrpUnlockTlsDelayedReclaimTable(ReleaseState);
    RtlLeaveCriticalSection(&FastPebLock);
    RtlpFlsCloneComplete(v19, ReleaseState);
    LdrpCompleteProcessCloning(ReleaseState);
    if ( ReleaseState )
    {
      LdrpForkInProgress = 0;
      RtlAcquireReleaseSRWLockExclusive(&LdrpForkActiveLock);
      RtlWakeAllConditionVariable(&LdrpForkConditionVariable);
    }
  }
  return ntstatus_1;
}
```

## RtlpCreateUserProcess

```c
__int64 __fastcall RtlpCreateUserProcess(
        PCUNICODE_STRING NtImagePathName,
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        ULONG ProcessFlags,
        ULONG ThreadFlags,
        PRTL_USER_PROCESS_EXTENDED_PARAMETERS ProcessExtendedParameters,
        PRTL_USER_PROCESS_INFORMATION ProcessInformation)
{
  unsigned int index; // ecx
  HANDLE ParentProcess; // rdx
  HANDLE DebugPort; // rdx
  HANDLE TokenHandle; // rdx
  USHORT NodeNumber; // ax
  __int64 protection_level_index; // rax
  signed int Flags; // eax
  __int64 node_preferred_index; // rax
  __int64 current_parent_process_index; // rax
  __int64 current_debug_port_index; // rax
  __int64 current_token_handle_index; // rax
  __int64 current_job_handle_index; // rax
  __int64 secure_process_index; // rax
  __int16 node_preferred; // [rsp+60h] [rbp-A0h] BYREF
  unsigned int v25; // [rsp+68h] [rbp-98h] BYREF
  PPS_TRUSTLET_CREATE_ATTRIBUTES PsAttributeSecureProcess; // [rsp+70h] [rbp-90h] BYREF
  OBJECT_ATTRIBUTES ThreadObjectAttributes; // [rsp+78h] [rbp-88h] BYREF
  OBJECT_ATTRIBUTES *ProcessObjectAttributes; // [rsp+A8h] [rbp-58h] BYREF
  __int64 v29; // [rsp+B0h] [rbp-50h]
  __int64 v30; // [rsp+B8h] [rbp-48h]
  int v31; // [rsp+C0h] [rbp-40h]
  PSECURITY_DESCRIPTOR ProcessSecurityDescriptor; // [rsp+C8h] [rbp-38h]
  __int64 v33; // [rsp+D0h] [rbp-30h]
  struct _PS_CREATE_INFO CreateInfo; // [rsp+E0h] [rbp-20h] BYREF
  struct _PS_ATTRIBUTE_LIST AttributeList; // [rsp+140h] [rbp+40h] BYREF
  __int64 v36; // [rsp+168h] [rbp+68h]
  __int64 v37; // [rsp+170h] [rbp+70h]
  SECTION_IMAGE_INFORMATION *p_ImageInformation; // [rsp+178h] [rbp+78h]
  __int64 v39; // [rsp+180h] [rbp+80h]
  __int64 v40; // [rsp+188h] [rbp+88h]
  __int64 Length; // [rsp+190h] [rbp+90h]
  wchar_t *Buffer; // [rsp+198h] [rbp+98h]
  __int64 v43; // [rsp+1A0h] [rbp+A0h]
  __int64 v44; // [rsp+1A8h] [rbp+A8h]
  __int64 v45; // [rsp+1B0h] [rbp+B0h]
  unsigned int *v46; // [rsp+1B8h] [rbp+B8h]
  __int64 v47; // [rsp+1C0h] [rbp+C0h]

  memset(&ProcessInformation->Length + 1, 0, 0x64u);
  ProcessInformation->Length = 104;
  if ( ProcessExtendedParameters && ProcessExtendedParameters->Version != 1 )
    return 3221225485LL;
  v29 = 0;
  LODWORD(ProcessObjectAttributes) = 48;
  v31 = 512;
  v30 = 0;
  if ( ProcessExtendedParameters )
    ProcessSecurityDescriptor = ProcessExtendedParameters->ProcessSecurityDescriptor;
  else
    ProcessSecurityDescriptor = 0;
  v33 = 0;
  ThreadObjectAttributes.Length = 48;
  ThreadObjectAttributes.RootDirectory = 0;
  ThreadObjectAttributes.Attributes = 512;
  ThreadObjectAttributes.ObjectName = 0;
  if ( ProcessExtendedParameters )
    ThreadObjectAttributes.SecurityDescriptor = ProcessExtendedParameters->ThreadSecurityDescriptor;
  else
    ThreadObjectAttributes.SecurityDescriptor = 0;
  ThreadObjectAttributes.SecurityQualityOfService = 0;
  PsAttributeSecureProcess = 0;
  memset(&CreateInfo.State, 0, 0x50u);
  *(_BYTE *)&CreateInfo.InitState.1 |= 4u;
  AttributeList.Attributes[0].Value = (ULONG_PTR)&ProcessInformation->ClientId;
  CreateInfo.Size = 88;
  p_ImageInformation = &ProcessInformation->ImageInformation;
  index = 2;
  AttributeList.Attributes[0].Attribute = 65539;
  AttributeList.Attributes[0].Size = 16;
  AttributeList.Attributes[0].ReturnLength = 0;
  v36 = 6;
  v37 = 64;
  v39 = 0;
  if ( NtImagePathName )
  {
    index = 4;
    Length = NtImagePathName->Length;
    Buffer = NtImagePathName->Buffer;
    v40 = 131077;
    v43 = 0;
    v25 = v25 & 0xFFFFFFE0 | 2;
    v46 = &v25;
    v44 = 131082;
    v45 = 8;
    v47 = 0;
  }
  if ( ProcessExtendedParameters )
  {
    ParentProcess = ProcessExtendedParameters->ParentProcess;
    if ( ParentProcess )
    {
      current_parent_process_index = index++;
      AttributeList.Attributes[current_parent_process_index].Attribute = 393216;// PS_ATTRIBUTE_PARENT_PROCESS
      AttributeList.Attributes[current_parent_process_index].Size = 8;
      AttributeList.Attributes[current_parent_process_index].ReturnLength = 0;
      *(ULONG_PTR *)((char *)&AttributeList.Attributes[0].Value + current_parent_process_index * 32) = (ULONG_PTR)ParentProcess;
    }
    DebugPort = ProcessExtendedParameters->DebugPort;
    if ( DebugPort )
    {
      current_debug_port_index = index++;
      AttributeList.Attributes[current_debug_port_index].Attribute = 393217;// PS_ATTRIBUTE_DEBUG_OBJECT
      AttributeList.Attributes[current_debug_port_index].Size = 8;
      AttributeList.Attributes[current_debug_port_index].ReturnLength = 0;
      *(ULONG_PTR *)((char *)&AttributeList.Attributes[0].Value + current_debug_port_index * 32) = (ULONG_PTR)DebugPort;
    }
    TokenHandle = ProcessExtendedParameters->TokenHandle;
    if ( TokenHandle )
    {
      current_token_handle_index = index++;
      AttributeList.Attributes[current_token_handle_index].Attribute = 393218;// PS_ATTRIBUTE_TOKEN
      AttributeList.Attributes[current_token_handle_index].Size = 8;
      AttributeList.Attributes[current_token_handle_index].ReturnLength = 0;
      *(ULONG_PTR *)((char *)&AttributeList.Attributes[0].Value + current_token_handle_index * 32) = (ULONG_PTR)TokenHandle;
    }
    if ( ProcessExtendedParameters->JobHandle )
    {
      current_job_handle_index = index++;
      AttributeList.Attributes[current_job_handle_index].Attribute = 131091;// PS_ATTRIBUTE_JOB_LIST
      AttributeList.Attributes[current_job_handle_index].Size = 8;
      AttributeList.Attributes[current_job_handle_index].ReturnLength = 0;
      *(ULONG_PTR *)((char *)&AttributeList.Attributes[0].Value + current_job_handle_index * 32) = (ULONG_PTR)&ProcessExtendedParameters->JobHandle;
    }
    NodeNumber = ProcessExtendedParameters->NodeNumber;
    if ( NodeNumber )
    {
      node_preferred = NodeNumber - 1;
      node_preferred_index = index++;
      AttributeList.Attributes[node_preferred_index].Attribute = 131085;// PS_ATTRIBUTE_PREFERRED_NODE
      AttributeList.Attributes[node_preferred_index].Size = 2;
      AttributeList.Attributes[node_preferred_index].ReturnLength = 0;
      *(ULONG_PTR *)((char *)&AttributeList.Attributes[0].Value + node_preferred_index * 32) = (ULONG_PTR)&node_preferred;
    }
    else
    {
      ProcessFlags |= 0x100u;
    }
  }
  if ( (ProcessFlags & 0x40) != 0 )
  {
    protection_level_index = index++;
    AttributeList.Attributes[protection_level_index].Attribute = 393233;// PS_ATTRIBUTE_PROTECTION_LEVEL
    AttributeList.Attributes[protection_level_index].Size = 1;
    AttributeList.Attributes[protection_level_index].ReturnLength = 0;
    *(ULONG_PTR *)((char *)&AttributeList.Attributes[0].Value + protection_level_index * 32) = 97;
  }
  if ( ProcessParameters )
  {
    Flags = ProcessParameters->Flags;
    if ( Flags < 0 )
    {
      ProcessParameters->Flags = Flags & 0x7FFFFFFF;
      secure_process_index = index++;
      AttributeList.Attributes[secure_process_index].Attribute = 131090;// PS_ATTRIBUTE_SECURE_PROCESS
      AttributeList.Attributes[secure_process_index].Size = 8;
      AttributeList.Attributes[secure_process_index].ReturnLength = 0;
      *(ULONG_PTR *)((char *)&AttributeList.Attributes[0].Value + secure_process_index * 32) = (ULONG_PTR)&PsAttributeSecureProcess;
    }
  }
  AttributeList.TotalLength = 32LL * index + 8;
  return NtCreateUserProcess(
           &ProcessInformation->ProcessHandle,
           &ProcessInformation->ThreadHandle,
           0x2000000u,
           0x2000000u,
           (PCOBJECT_ATTRIBUTES)&ProcessObjectAttributes,
           &ThreadObjectAttributes,
           ProcessFlags,
           ThreadFlags,
           ProcessParameters,
           &CreateInfo,
           &AttributeList);
}
```

## RtlpCreateUserThreadEx

```c
// local variable allocation has failed, the output may be wrong!
__int64 __fastcall RtlpCreateUserThreadEx(
        HANDLE ProcessHandle,
        PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
        BOOLEAN CreateSuspended,
        ULONG ZeroBits,
        SIZE_T MaximumStackSize,
        SIZE_T CommittedStackSize,
        PVOID StartAdd,
        PVOID Parameter,
        PHANDLE ThreadHandle,
        PCLIENT_ID ClientId)
{
  SIZE_T ZeroBits_1; // rsi
  int v13; // edx
  int v14; // ecx
  int v15; // edx
  ULONG create_flags_tmp; // r8d
  ULONG CreateFlags; // ecx
  __int64 result; // rax
  HANDLE Handle; // [rsp+60h] [rbp-A0h] BYREF
  ULONG_PTR v21; // [rsp+68h] [rbp-98h] OVERLAPPED BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+78h] [rbp-88h] BYREF
  PS_ATTRIBUTE_LIST AttributeList; // [rsp+B0h] [rbp-50h] BYREF
  PVOID v24; // [rsp+190h] [rbp+90h]

  ZeroBits_1 = ZeroBits;
  *(_OWORD *)&v21 = 0;
  if ( (CreateSuspended & 0xFFFFFF88) != 0 )
    return 3221225485LL;
  ObjectAttributes.Length = 48;
  ObjectAttributes.Attributes = 512;
  ObjectAttributes.SecurityDescriptor = ThreadSecurityDescriptor;
  AttributeList.Attributes[0].Attribute = 65539;
  v13 = CreateSuspended & 1 | 2;
  AttributeList.Attributes[0].Size = 16;
  AttributeList.TotalLength = 40;
  if ( (CreateSuspended & 2) == 0 )
    v13 = CreateSuspended & 1;
  v14 = v13 | 4;
  if ( (CreateSuspended & 4) == 0 )
    v14 = v13;
  v15 = v14 | 0x10;
  if ( (CreateSuspended & 0x10) == 0 )
    v15 = v14;
  create_flags_tmp = v15 | 0x20;
  if ( (CreateSuspended & 0x20) == 0 )
    create_flags_tmp = v15;
  AttributeList.Attributes[0].Value = (ULONG_PTR)&v21;
  ObjectAttributes.RootDirectory = 0;
  ObjectAttributes.ObjectName = 0;
  ObjectAttributes.SecurityQualityOfService = 0;
  CreateFlags = create_flags_tmp | 0x40;
  AttributeList.Attributes[0].ReturnLength = 0;
  if ( (CreateSuspended & 0x40) == 0 )
    CreateFlags = create_flags_tmp;
  result = NtCreateThreadEx(
             &Handle,
             0x1FFFFF,
             &ObjectAttributes,
             ProcessHandle,
             Parameter,
             ThreadHandle,
             CreateFlags,
             ZeroBits_1,
             CommittedStackSize,
             MaximumStackSize,
             &AttributeList);
  if ( (int)result >= 0 )
  {
    if ( ClientId )
      ClientId->UniqueProcess = Handle;
    else
      NtClose(Handle);
    if ( v24 )
      *(_OWORD *)v24 = *(_OWORD *)&v21;
    return 0;
  }
  return result;
}
```


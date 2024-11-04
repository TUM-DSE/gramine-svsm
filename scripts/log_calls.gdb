break console_open
commands
silent
printf "console_open called\n"
continue
end

break console_read
commands
silent
printf "console_read called\n"
continue
end

break console_write
commands
silent
printf "console_write called\n"
continue
end

break console_destroy
commands
silent
printf "console_destroy called\n"
continue
end

break console_flush
commands
silent
printf "console_flush called\n"
continue
end

break dev_open
commands
silent
printf "dev_open called\n"
continue
end

break dev_read
commands
silent
printf "dev_read called\n"
continue
end

break dev_write
commands
silent
printf "dev_write called\n"
continue
end

break dev_destroy
commands
silent
printf "dev_destroy called\n"
continue
end

break dev_delete
commands
silent
printf "dev_delete called\n"
continue
end

break dev_setlength
commands
silent
printf "dev_setlength called\n"
continue
end

break dev_flush
commands
silent
printf "dev_flush called\n"
continue
end

break dev_attrquery
commands
silent
printf "dev_attrquery called\n"
continue
end

break dev_attrquerybyhdl
commands
silent
printf "dev_attrquerybyhdl called\n"
continue
end

break dev_map
commands
silent
printf "dev_map called\n"
continue
end

break _PalDeviceIoControl
commands
silent
printf "_PalDeviceIoControl called\n"
continue
end

break eventfd_pal_open
commands
silent
printf "eventfd_pal_open called\n"
continue
end

break eventfd_pal_read
commands
silent
printf "eventfd_pal_read called\n"
continue
end

break eventfd_pal_write
commands
silent
printf "eventfd_pal_write called\n"
continue
end

break eventfd_pal_attrquerybyhdl
commands
silent
printf "eventfd_pal_attrquerybyhdl called\n"
continue
end

break eventfd_pal_destroy
commands
silent
printf "eventfd_pal_destroy called\n"
continue
end

break _PalEventCreate
commands
silent
printf "_PalEventCreate called\n"
continue
end

break _PalEventSet
commands
silent
printf "_PalEventSet called\n"
continue
end

break _PalEventClear
commands
silent
printf "_PalEventClear called\n"
continue
end

break _PalEventWait
commands
silent
printf "_PalEventWait called\n"
continue
end

break event_destroy
commands
silent
printf "event_destroy called\n"
continue
end

break file_open
commands
silent
printf "file_open called\n"
continue
end

break file_read
commands
silent
printf "file_read called\n"
continue
end

break file_write
commands
silent
printf "file_write called\n"
continue
end

break file_destroy
commands
silent
printf "file_destroy called\n"
continue
end

break file_delete
commands
silent
printf "file_delete called\n"
continue
end

break file_map
commands
silent
printf "file_map called\n"
continue
end

break file_setlength
commands
silent
printf "file_setlength called\n"
continue
end

break file_flush
commands
silent
printf "file_flush called\n"
continue
end

break file_attrquery
commands
silent
printf "file_attrquery called\n"
continue
end

break file_attrquerybyhdl
commands
silent
printf "file_attrquerybyhdl called\n"
continue
end

break file_rename
commands
silent
printf "file_rename called\n"
continue
end

break dir_open
commands
silent
printf "dir_open called\n"
continue
end

break dir_read
commands
silent
printf "dir_read called\n"
continue
end

break dir_destroy
commands
silent
printf "dir_destroy called\n"
continue
end

break dir_delete
commands
silent
printf "dir_delete called\n"
continue
end

break dir_attrquerybyhdl
commands
silent
printf "dir_attrquerybyhdl called\n"
continue
end

break dir_rename
commands
silent
printf "dir_rename called\n"
continue
end

break _PalVirtualMemoryAlloc
commands
silent
printf "_PalVirtualMemoryAlloc called\n"
continue
end

break _PalVirtualMemoryFree
commands
silent
printf "_PalVirtualMemoryFree called\n"
continue
end

break _PalVirtualMemoryProtect
commands
silent
printf "_PalVirtualMemoryProtect called\n"
continue
end

break _PalMemoryQuota
commands
silent
printf "_PalMemoryQuota called\n"
continue
end

break pal_read_next_reserved_range
commands
silent
printf "pal_read_next_reserved_range called\n"
continue
end

break _PalSystemTimeQuery
commands
silent
printf "_PalSystemTimeQuery called\n"
continue
end

break _PalRandomBitsRead
commands
silent
printf "_PalRandomBitsRead called\n"
continue
end

break _PalSegmentBaseGet
commands
silent
printf "_PalSegmentBaseGet called\n"
continue
end

break _PalSegmentBaseSet
commands
silent
printf "_PalSegmentBaseSet called\n"
continue
end

break _PalCpuIdRetrieve
commands
silent
printf "_PalCpuIdRetrieve called\n"
continue
end

break _PalAttestationReport
commands
silent
printf "_PalAttestationReport called\n"
continue
end

break _PalAttestationQuote
commands
silent
printf "_PalAttestationQuote called\n"
continue
end

break _PalGetSpecialKey
commands
silent
printf "_PalGetSpecialKey called\n"
continue
end

break _PalGetBogomips
commands
silent
printf "_PalGetBogomips called\n"
continue
end

break _PalStreamsWaitEvents
commands
silent
printf "_PalStreamsWaitEvents called\n"
continue
end

break pipe_listen
commands
silent
printf "pipe_listen called\n"
continue
end

break pipe_waitforclient
commands
silent
printf "pipe_waitforclient called\n"
continue
end

break pipe_connect
commands
silent
printf "pipe_connect called\n"
continue
end

break pipe_open
commands
silent
printf "pipe_open called\n"
continue
end

break pipe_read
commands
silent
printf "pipe_read called\n"
continue
end

break pipe_write
commands
silent
printf "pipe_write called\n"
continue
end

break pipe_destroy
commands
silent
printf "pipe_destroy called\n"
continue
end

break pipe_delete
commands
silent
printf "pipe_delete called\n"
continue
end

break _PalProcessCreate
commands
silent
printf "_PalProcessCreate called\n"
continue
end

break _PalProcessExit
commands
silent
printf "_PalProcessExit called\n"
continue
end

break proc_read
commands
silent
printf "proc_read called\n"
continue
end

break proc_write
commands
silent
printf "proc_write called\n"
continue
end

break proc_destroy
commands
silent
printf "proc_destroy called\n"
continue
end

break _PalDebugMapAdd
commands
silent
printf "_PalDebugMapAdd called\n"
continue
end

break _PalDebugMapRemove
commands
silent
printf "_PalDebugMapRemove called\n"
continue
end

break _PalDebugDescribeLocation
commands
silent
printf "_PalDebugDescribeLocation called\n"
continue
end

break _PalSocketCreate
commands
silent
printf "_PalSocketCreate called\n"
continue
end

break _PalSocketBind
commands
silent
printf "_PalSocketBind called\n"
continue
end

break _PalSocketListen
commands
silent
printf "_PalSocketListen called\n"
continue
end

break _PalSocketAccept
commands
silent
printf "_PalSocketAccept called\n"
continue
end

break _PalSocketConnect
commands
silent
printf "_PalSocketConnect called\n"
continue
end

break _PalSocketSend
commands
silent
printf "_PalSocketSend called\n"
continue
end

break _PalSocketRecv
commands
silent
printf "_PalSocketRecv called\n"
continue
end

break _PalSendHandle
commands
silent
printf "_PalSendHandle called\n"
continue
end

break _PalReceiveHandle
commands
silent
printf "_PalReceiveHandle called\n"
continue
end

break _PalInitDebugStream
commands
silent
printf "_PalInitDebugStream called\n"
continue
end

break _PalDebugLog
commands
silent
printf "_PalDebugLog called\n"
continue
end

break _PalThreadCreate
commands
silent
printf "_PalThreadCreate called\n"
continue
end

break _PalThreadYieldExecution
commands
silent
printf "_PalThreadYieldExecution called\n"
continue
end

break _PalThreadExit
commands
silent
printf "_PalThreadExit called\n"
continue
end

break _PalThreadResume
commands
silent
printf "_PalThreadResume called\n"
continue
end

break _PalThreadSetCpuAffinity
commands
silent
printf "_PalThreadSetCpuAffinity called\n"
continue
end

break _PalThreadGetCpuAffinity
commands
silent
printf "_PalThreadGetCpuAffinity called\n"
continue
end

set logging file gdb.log
set logging enabled on

run

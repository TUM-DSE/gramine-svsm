# Functions to implement

* `pal_start()`
   * calls the main function for the architecture specific implementation (e.g. `pal_svsm_main()`).

* `pal_svsm_main()`
    * set up all necessary components to be able to call `pal_main()`
    * make sure stack is initialized with canary if needed
    * call `setup_pal_binary()` which should be already be implemented.
    * do some preliminary work on the manifest (`pal_main` expects this to be done here)
    * turn off ASLR (by execve-ing yourself)
    * start the first thread

#### Essential `_Pal` implementations

* `_PalSystemTimeQuery()`
    * get current time in microseconds
* `_PalVirtualMemoryAlloc()`
    * allocate memory at an alligned address and zero it (we will probably restrict ourselves to page sizes)
* `_PalRandomBitsRead()`
    * generate a sequence of cryptographically secure numbers. Can probably use `RDRAND` for implementing this.
* `_PalGetCPUInfo()`
* `_PalCpuIdRetrieve()`
* `_PalGetBogomips()`
* `_PalMemoryQuota()`
* `_PalStreamOpen()`
    * open/create a stream resource specified by a URI
    * done via ops pointer
* `_PalStreamRead()`
    * via ops pointer
* `_PalStreamMap()`
    * map a file to a VA in the current process
    * via ops pointer
* `_PalVirtualMemoryProtect()`
    * modify permissions of a previously allocated memory mapping
* `_PalDebugMapAdd()`
    * we can probably ignore this
* `_PalObjectDestroy()`
    * via ops pointer
* `_PalEventCreate()`
    * Create an event handle (resemles WinAPI synchronization events)
* `_PalEventWait()`
    * wait for an event to be signaled
* `_PalEventSet()`
    * signal an event
* `_PalStreamWaitForClient()`
    * block until a new connection is accepted
* `_PalStreamDelete()`
    * via ops pointer
* `_PalThreadGetCpuAffinity()`
* `_PalStreamAttributesQuery()`
* `_PalThreadCreate()`
* `_PalStreamsWaitEvents()`
    * wait for an event to happen on at least one handle
* `_PalSegmentBaseSet()`
    * set segment register
* `_PalVirtualMemoryFree()`
    * Deallocate a previously allocated memory mapping. Addr and size must be aligned. No holes.
* `_PalStreamWrite()`
    * via ops pointer
* `_PalThreadYieldExecution()`
* `_PalThreadExit()`
* `_PalProcessExit()`

> *Note on ops pointer*: `handle_ops` struct contains pointers to specific file or directory functions. Some of the `_Pal` functions already call the appropriate ops. Just the functions/function pointers need to be implemented/set.




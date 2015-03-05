#include "stdafx.h"
#include "Emu/Memory/Memory.h"
#include "Emu/System.h"
#include "Emu/CPU/CPUThreadManager.h"
#include "Emu/SysCalls/Modules.h"
#include "Emu/SysCalls/CB_FUNC.h"
#include "Emu/Memory/atomic_type.h"

#include "Emu/Cell/SPUThread.h"
#include "Emu/SysCalls/lv2/sleep_queue_type.h"
#include "Emu/SysCalls/lv2/sys_lwmutex.h"
#include "Emu/SysCalls/lv2/sys_lwcond.h"
#include "Emu/SysCalls/lv2/sys_spu.h"
#include "Emu/SysCalls/lv2/sys_ppu_thread.h"
#include "Emu/SysCalls/lv2/sys_memory.h"
#include "Emu/SysCalls/lv2/sys_process.h"
#include "Emu/SysCalls/lv2/sys_semaphore.h"
#include "Emu/SysCalls/lv2/sys_event.h"
#include "sysPrxForUser.h"
#include "cellSpurs.h"

//----------------------------------------------------------------------------
// Externs
//----------------------------------------------------------------------------

extern Module cellSpurs;

//----------------------------------------------------------------------------
// Function prototypes
//----------------------------------------------------------------------------

//
// SPURS SPU functions
//
bool spursKernelEntry(SPUThread & spu);

//
// SPURS utility functions
//
void spursPpuThreadExit(u64 errorStatus);
u32 spursGetSdkVersion();
bool spursIsLibProfLoaded();

//
// SPURS core functions
//
s32 spursCreateLv2EventQueue(vm::ptr<CellSpurs> spurs, vm::ptr<u32> queueId, vm::ptr<u8> port, s32 size, vm::ptr<const char> name);
s32 spursAttachLv2EventQueue(vm::ptr<CellSpurs> spurs, u32 queue, vm::ptr<u8> port, s32 isDynamic, bool spursCreated);
s32 spursDetachLv2EventQueue(vm::ptr<CellSpurs> spurs, u8 spuPort, bool spursCreated);
void spursHandlerWaitReady(vm::ptr<CellSpurs> spurs);
void spursHandlerEntry(PPUThread & ppu);
s32 spursCreateHandler(vm::ptr<CellSpurs> spurs, u32 ppuPriority);
s32 spursInvokeEventHandlers(vm::ptr<CellSpurs::EventPortMux> eventPortMux);
s32 spursWakeUpShutdownCompletionWaiter(vm::ptr<CellSpurs> spurs, u32 wid);
void spursEventHelperEntry(PPUThread & ppu);
s32 spursCreateSpursEventHelper(vm::ptr<CellSpurs> spurs, u32 ppuPriority);
void spursInitialiseEventPortMux(vm::ptr<CellSpurs::EventPortMux> eventPortMux, u8 spuPort, u32 eventPort, u32 unknown);
s32 spursAddDefaultSystemWorkload(vm::ptr<CellSpurs> spurs, vm::ptr<const u8> swlPriority, u32 swlMaxSpu, u32 swlIsPreem);
s32 spursFinalizeSpu(vm::ptr<CellSpurs> spurs);
s32 spursStopEventHelper(vm::ptr<CellSpurs> spurs);
s32 spursSignalToHandlerThread(vm::ptr<CellSpurs> spurs);
s32 spursJoinHandlerThread(vm::ptr<CellSpurs> spurs);
s32 spursInit(vm::ptr<CellSpurs> spurs, const u32 revision, const u32 sdkVersion, const s32 nSpus, const s32 spuPriority, const s32 ppuPriority, u32 flags,
	vm::ptr<const char> prefix, const u32 prefixSize, const u32 container, vm::ptr<const u8> swlPriority, const u32 swlMaxSpu, const u32 swlIsPreem);
s32 cellSpursInitialize(vm::ptr<CellSpurs> spurs, s32 nSpus, s32 spuPriority, s32 ppuPriority, bool exitIfNoWork);
s32 cellSpursInitializeWithAttribute(vm::ptr<CellSpurs> spurs, vm::ptr<const CellSpursAttribute> attr);
s32 cellSpursInitializeWithAttribute2(vm::ptr<CellSpurs> spurs, vm::ptr<const CellSpursAttribute> attr);
s32 _cellSpursAttributeInitialize(vm::ptr<CellSpursAttribute> attr, u32 revision, u32 sdkVersion, u32 nSpus, s32 spuPriority, s32 ppuPriority, bool exitIfNoWork);
s32 cellSpursAttributeSetMemoryContainerForSpuThread(vm::ptr<CellSpursAttribute> attr, u32 container);
s32 cellSpursAttributeSetNamePrefix(vm::ptr<CellSpursAttribute> attr, vm::ptr<const char> prefix, u32 size);
s32 cellSpursAttributeEnableSpuPrintfIfAvailable(vm::ptr<CellSpursAttribute> attr);
s32 cellSpursAttributeSetSpuThreadGroupType(vm::ptr<CellSpursAttribute> attr, s32 type);
s32 cellSpursAttributeEnableSystemWorkload(vm::ptr<CellSpursAttribute> attr, vm::ptr<const u8[8]> priority, u32 maxSpu, vm::ptr<const bool[8]> isPreemptible);
s32 cellSpursFinalize(vm::ptr<CellSpurs> spurs);
s32 cellSpursGetSpuThreadGroupId(vm::ptr<CellSpurs> spurs, vm::ptr<u32> group);
s32 cellSpursGetNumSpuThread(vm::ptr<CellSpurs> spurs, vm::ptr<u32> nThreads);
s32 cellSpursGetSpuThreadId(vm::ptr<CellSpurs> spurs, vm::ptr<u32> thread, vm::ptr<u32> nThreads);
s32 cellSpursSetMaxContention(vm::ptr<CellSpurs> spurs, u32 workloadId, u32 maxContention);
s32 cellSpursSetPriorities(vm::ptr<CellSpurs> spurs, u32 workloadId, vm::ptr<const u8> priorities);
s32 cellSpursSetPreemptionVictimHints(vm::ptr<CellSpurs> spurs, vm::ptr<const bool> isPreemptible);
s32 cellSpursAttachLv2EventQueue(vm::ptr<CellSpurs> spurs, u32 queue, vm::ptr<u8> port, s32 isDynamic);
s32 cellSpursDetachLv2EventQueue(vm::ptr<CellSpurs> spurs, u8 port);
s32 cellSpursEnableExceptionEventHandler(vm::ptr<CellSpurs> spurs, bool flag);
s32 cellSpursSetGlobalExceptionEventHandler(vm::ptr<CellSpurs> spurs, vm::ptr<void> eaHandler, vm::ptr<void> arg);
s32 cellSpursUnsetGlobalExceptionEventHandler(vm::ptr<CellSpurs> spurs);
s32 cellSpursGetInfo(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursInfo> info);

//
// SPURS SPU GUID functions
//
s32 cellSpursGetSpuGuid();

//
// SPURS trace functions
//
void spursTraceStatusUpdate(vm::ptr<CellSpurs> spurs);
s32 spursTraceInitialize(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTraceInfo> buffer, u32 size, u32 mode, u32 updateStatus);
s32 cellSpursTraceInitialize(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTraceInfo> buffer, u32 size, u32 mode);
s32 cellSpursTraceFinalize(vm::ptr<CellSpurs> spurs);
s32 spursTraceStart(vm::ptr<CellSpurs> spurs, u32 updateStatus);
s32 cellSpursTraceStart(vm::ptr<CellSpurs> spurs);
s32 spursTraceStop(vm::ptr<CellSpurs> spurs, u32 updateStatus);
s32 cellSpursTraceStop(vm::ptr<CellSpurs> spurs);

//
// SPURS policy module functions
//
s32 spursWakeUp(PPUThread& CPU, vm::ptr<CellSpurs> spurs);
s32 cellSpursWakeUp(PPUThread& CPU, vm::ptr<CellSpurs> spurs);
s32 spursAddWorkload(vm::ptr<CellSpurs> spurs, vm::ptr<u32> wid, vm::ptr<const void> pm, u32 size, u64 data, const u8 priorityTable[],
	u32 minContention, u32 maxContention,vm::ptr<const char> nameClass, vm::ptr<const char> nameInstance, vm::ptr<u64> hook, vm::ptr<void> hookArg);
s32 cellSpursAddWorkload(vm::ptr<CellSpurs> spurs, vm::ptr<u32> wid, vm::ptr<const void> pm, u32 size, u64 data, vm::ptr<const u8[8]> priorityTable,
	u32 minContention, u32 maxContention);
s32 _cellSpursWorkloadAttributeInitialize(vm::ptr<CellSpursWorkloadAttribute> attr, u32 revision, u32 sdkVersion, vm::ptr<const void> pm, u32 size,
	u64 data, vm::ptr<const u8[8]> priorityTable, u32 minContention, u32 maxContention);
s32 cellSpursWorkloadAttributeSetName(vm::ptr<CellSpursWorkloadAttribute> attr, vm::ptr<const char> nameClass, vm::ptr<const char> nameInstance);
s32 cellSpursWorkloadAttributeSetShutdownCompletionEventHook(vm::ptr<CellSpursWorkloadAttribute> attr, vm::ptr<CellSpursShutdownCompletionEventHook> hook, vm::ptr<void> arg);
s32 cellSpursAddWorkloadWithAttribute(vm::ptr<CellSpurs> spurs, const vm::ptr<u32> wid, vm::ptr<const CellSpursWorkloadAttribute> attr);
s32 cellSpursRemoveWorkload();
s32 cellSpursWaitForWorkloadShutdown();
s32 cellSpursShutdownWorkload();
s32 _cellSpursWorkloadFlagReceiver(vm::ptr<CellSpurs> spurs, u32 wid, u32 is_set);
s32 cellSpursGetWorkloadFlag(vm::ptr<CellSpurs> spurs, vm::ptr<vm::bptr<CellSpursWorkloadFlag>> flag);
s32 cellSpursSendWorkloadSignal(vm::ptr<CellSpurs> spurs, u32 workloadId);
s32 cellSpursGetWorkloadData(vm::ptr<CellSpurs> spurs, vm::ptr<u64> data, u32 workloadId);
s32 cellSpursReadyCountStore(vm::ptr<CellSpurs> spurs, u32 wid, u32 value);
s32 cellSpursReadyCountAdd();
s32 cellSpursReadyCountCompareAndSwap();
s32 cellSpursReadyCountSwap();
s32 cellSpursRequestIdleSpu();
s32 cellSpursGetWorkloadInfo();
s32 _cellSpursWorkloadFlagReceiver2();
s32 cellSpursSetExceptionEventHandler();
s32 cellSpursUnsetExceptionEventHandler();

//
// SPURS taskset functions
//
s32 spursCreateTaskset(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, u64 args, vm::ptr<const u8[8]> priority,
	u32 max_contention, vm::ptr<const char> name, u32 size, s32 enable_clear_ls);
s32 cellSpursCreateTasksetWithAttribute(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, vm::ptr<CellSpursTasksetAttribute> attr);
s32 cellSpursCreateTaskset(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, u64 args, vm::ptr<const u8[8]> priority, u32 maxContention);
s32 cellSpursJoinTaskset(vm::ptr<CellSpursTaskset> taskset);
s32 cellSpursGetTasksetId(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u32> wid);
s32 cellSpursShutdownTaskset(vm::ptr<CellSpursTaskset> taskset);
s32 cellSpursTasksetAttributeSetName(vm::ptr<CellSpursTasksetAttribute> attr, vm::ptr<const char> name);
s32 cellSpursTasksetAttributeSetTasksetSize(vm::ptr<CellSpursTasksetAttribute> attr, u32 size);
s32 cellSpursTasksetAttributeEnableClearLS(vm::ptr<CellSpursTasksetAttribute> attr, s32 enable);
s32 _cellSpursTasksetAttribute2Initialize(vm::ptr<CellSpursTasksetAttribute2> attribute, u32 revision);
s32 cellSpursCreateTaskset2(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset2> taskset, vm::ptr<CellSpursTasksetAttribute2> attr);
s32 cellSpursDestroyTaskset2();
s32 cellSpursTasksetSetExceptionEventHandler(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u64> handler, vm::ptr<u64> arg);
s32 cellSpursTasksetUnsetExceptionEventHandler(vm::ptr<CellSpursTaskset> taskset);
s32 cellSpursLookUpTasksetAddress(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, u32 id);
s32 cellSpursTasksetGetSpursAddress(vm::ptr<const CellSpursTaskset> taskset, vm::ptr<u32> spurs);
s32 cellSpursGetTasksetInfo();
s32 _cellSpursTasksetAttributeInitialize(vm::ptr<CellSpursTasksetAttribute> attribute, u32 revision, u32 sdk_version, u64 args, vm::ptr<const u8> priority, u32 max_contention);

//
// SPURS task functions
//
s32 spursCreateTask(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u32> task_id, vm::ptr<u32> elf_addr, vm::ptr<u32> context_addr, u32 context_size, vm::ptr<CellSpursTaskLsPattern> ls_pattern, vm::ptr<CellSpursTaskArgument> arg);
s32 spursTaskStart(vm::ptr<CellSpursTaskset> taskset, u32 taskId);
s32 cellSpursCreateTask(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u32> taskId, u32 elf_addr, u32 context_addr, u32 context_size, vm::ptr<CellSpursTaskLsPattern> lsPattern,
	vm::ptr<CellSpursTaskArgument> argument);
s32 _cellSpursSendSignal(vm::ptr<CellSpursTaskset> taskset, u32 taskId);
s32 cellSpursCreateTaskWithAttribute();
s32 cellSpursTaskExitCodeGet();
s32 cellSpursTaskExitCodeInitialize();
s32 cellSpursTaskExitCodeTryGet();
s32 cellSpursTaskGetLoadableSegmentPattern();
s32 cellSpursTaskGetReadOnlyAreaPattern();
s32 cellSpursTaskGenerateLsPattern();
s32 _cellSpursTaskAttributeInitialize();
s32 cellSpursTaskAttributeSetExitCodeContainer();
s32 _cellSpursTaskAttribute2Initialize(vm::ptr<CellSpursTaskAttribute2> attribute, u32 revision);
s32 cellSpursTaskGetContextSaveAreaSize();
s32 cellSpursCreateTask2();
s32 cellSpursJoinTask2();
s32 cellSpursTryJoinTask2();
s32 cellSpursCreateTask2WithBinInfo();

//
// SPURS event flag functions
//
s32 _cellSpursEventFlagInitialize(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, vm::ptr<CellSpursEventFlag> eventFlag, u32 flagClearMode, u32 flagDirection);
s32 cellSpursEventFlagAttachLv2EventQueue(vm::ptr<CellSpursEventFlag> eventFlag);
s32 cellSpursEventFlagDetachLv2EventQueue(vm::ptr<CellSpursEventFlag> eventFlag);
s32 _cellSpursEventFlagWait(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u16> mask, u32 mode, u32 block);
s32 cellSpursEventFlagWait(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u16> mask, u32 mode);
s32 cellSpursEventFlagClear(vm::ptr<CellSpursEventFlag> eventFlag, u16 bits);
s32 cellSpursEventFlagSet(vm::ptr<CellSpursEventFlag> eventFlag, u16 bits);
s32 cellSpursEventFlagTryWait(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u16> mask, u32 mode);
s32 cellSpursEventFlagGetDirection(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u32> direction);
s32 cellSpursEventFlagGetClearMode(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u32> clear_mode);
s32 cellSpursEventFlagGetTasksetAddress(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<CellSpursTaskset> taskset);

//
// SPURS lock free queue functions
//
s32 _cellSpursLFQueueInitialize();
s32 _cellSpursLFQueuePushBody();
s32 cellSpursLFQueueDetachLv2EventQueue();
s32 cellSpursLFQueueAttachLv2EventQueue();
s32 _cellSpursLFQueuePopBody();
s32 cellSpursLFQueueGetTasksetAddress();

//
// SPURS queue functions
//
s32 _cellSpursQueueInitialize();
s32 cellSpursQueuePopBody();
s32 cellSpursQueuePushBody();
s32 cellSpursQueueAttachLv2EventQueue();
s32 cellSpursQueueDetachLv2EventQueue();
s32 cellSpursQueueGetTasksetAddress();
s32 cellSpursQueueClear();
s32 cellSpursQueueDepth();
s32 cellSpursQueueGetEntrySize();
s32 cellSpursQueueSize();
s32 cellSpursQueueGetDirection();

//
// SPURS barrier functions
//
s32 cellSpursBarrierInitialize();
s32 cellSpursBarrierGetTasksetAddress();

//
// SPURS semaphore functions
//
s32 _cellSpursSemaphoreInitialize();
s32 cellSpursSemaphoreGetTasksetAddress();

//
// SPURS job chain functions
//
s32 cellSpursCreateJobChainWithAttribute();
s32 cellSpursCreateJobChain();
s32 cellSpursJoinJobChain();
s32 cellSpursKickJobChain();
s32 _cellSpursJobChainAttributeInitialize();
s32 cellSpursGetJobChainId();
s32 cellSpursJobChainSetExceptionEventHandler();
s32 cellSpursJobChainUnsetExceptionEventHandler();
s32 cellSpursGetJobChainInfo();
s32 cellSpursJobChainGetSpursAddress();
s32 cellSpursJobGuardInitialize();
s32 cellSpursJobChainAttributeSetName();
s32 cellSpursShutdownJobChain();
s32 cellSpursJobChainAttributeSetHaltOnError();
s32 cellSpursJobChainAttributeSetJobTypeMemoryCheck();
s32 cellSpursJobGuardNotify();
s32 cellSpursJobGuardReset();
s32 cellSpursRunJobChain();
s32 cellSpursJobChainGetError();
s32 cellSpursGetJobPipelineInfo();
s32 cellSpursJobSetMaxGrab();
s32 cellSpursJobHeaderSetJobbin2Param();
s32 cellSpursAddUrgentCommand();
s32 cellSpursAddUrgentCall();

//----------------------------------------------------------------------------
// SPURS utility functions
//----------------------------------------------------------------------------

/// Terminate a SPURS PPU thread
void spursPpuThreadExit(u64 errorStatus)
{
	sys_ppu_thread_exit(GetCurrentPPUThread(), errorStatus);
	throw SpursModuleExit();
}

/// Get the version of SDK used by this process
u32 spursGetSdkVersion()
{
	vm::var<s32> version;
	if (sys_process_get_sdk_version(sys_process_getpid(), version) != CELL_OK)
	{
		assert(0);
	}

	return version == -1 ? 0x465000 : version;
}

/// Check whether libprof is loaded
bool spursIsLibProfLoaded()
{
	return false;
}

//----------------------------------------------------------------------------
// SPURS core functions
//----------------------------------------------------------------------------

/// Create an LV2 event queue and attach it to the SPURS instance
s32 spursCreateLv2EventQueue(vm::ptr<CellSpurs> spurs, vm::ptr<u32> queueId, vm::ptr<u8> port, s32 size, vm::ptr<const char> name)
{
	vm::var<sys_event_queue_attr> attr;

	sys_event_queue_attribute_initialize(attr);
	memcpy(attr->name, name.get_ptr(), sizeof(attr->name));
	auto rc = sys_event_queue_create(queueId, attr, SYS_EVENT_QUEUE_LOCAL, size);
	if (rc != CELL_OK)
	{
		return rc;
	}

	vm::var<u8> _port;
	rc = spursAttachLv2EventQueue(spurs, *queueId, _port, 1/*isDynamic*/, true/*spursCreated*/);
	if (rc != CELL_OK)
	{
		sys_event_queue_destroy(*queueId, SYS_EVENT_QUEUE_DESTROY_FORCE);
	}

	*port = _port;
	return CELL_OK;
}

/// Attach an LV2 event queue to the SPURS instance
s32 spursAttachLv2EventQueue(vm::ptr<CellSpurs> spurs, u32 queue, vm::ptr<u8> port, s32 isDynamic, bool spursCreated)
{
	if (!spurs || !port)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (spurs->m.exception.data())
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	s32 sdkVer   = spursGetSdkVersion();
	u8 _port     = 0x3f;
	u64 portMask = 0;

	if (isDynamic == 0)
	{
		_port = *port;
		if (_port > 0x3f)
		{
			return CELL_SPURS_CORE_ERROR_INVAL;
		}

		if (sdkVer >= 0x180000 && _port > 0xf)
		{
			return CELL_SPURS_CORE_ERROR_PERM;
		}
	}

	for (u32 i = isDynamic ? 0x10 : _port; i <= _port; i++)
	{
		portMask |= 1ull << (i);
	}

	vm::var<u8> connectedPort;
	if (s32 res = sys_spu_thread_group_connect_event_all_threads(spurs->m.spuTG, queue, portMask, connectedPort))
	{
		if (res == CELL_EISCONN)
		{
			return CELL_SPURS_CORE_ERROR_BUSY;
		}

		return res;
	}

	*port = connectedPort;
	if (!spursCreated)
	{
		spurs->m.spuPortBits |= be_t<u64>::make(1ull << connectedPort);
	}

	return CELL_OK;
}

/// Detach an LV2 event queue from the SPURS instance
s32 spursDetachLv2EventQueue(vm::ptr<CellSpurs> spurs, u8 spuPort, bool spursCreated)
{
	if (spurs.addr() == 0)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (spursCreated == false && spurs->m.exception)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	if (spuPort > 0x3F)
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	auto sdkVer = spursGetSdkVersion();
	if (!spursCreated)
	{
		auto mask = 1ull << spuPort;
		if (sdkVer >= 0x180000)
		{
			if ((spurs->m.spuPortBits.read_relaxed() & mask) == 0)
			{
				return CELL_SPURS_CORE_ERROR_SRCH;
			}
		}

		spurs->m.spuPortBits &= be_t<u64>::make(~mask);
	}

	return CELL_OK;
}

/// Wait until a workload in the SPURS instance becomes ready
void spursHandlerWaitReady(vm::ptr<CellSpurs> spurs)
{
	auto rc = sys_lwmutex_lock(GetCurrentPPUThread(), spurs->get_lwmutex(), 0);
	assert(rc == CELL_OK);

	while (true)
	{
		if (Emu.IsStopped())
		{
			spursPpuThreadExit(0);
		}

		if (spurs->m.handlerExiting.read_relaxed())
		{
			rc = sys_lwmutex_unlock(GetCurrentPPUThread(), spurs->get_lwmutex());
			assert(rc == CELL_OK);

			spursPpuThreadExit(0);
		}

		// Find a runnable workload
		spurs->m.handlerDirty.write_relaxed(0);
		if (spurs->m.exception == 0)
		{
			bool foundRunnableWorkload = false;
			for (u32 i = 0; i < 16; i++)
			{
				if (spurs->m.wklState1[i].read_relaxed() == SPURS_WKL_STATE_RUNNABLE &&
					*((u64 *)spurs->m.wklInfo1[i].priority) != 0 &&
					spurs->m.wklMaxContention[i].read_relaxed() & 0x0F)
				{
					if (spurs->m.wklReadyCount1[i].read_relaxed() ||
						spurs->m.wklSignal1.read_relaxed() & (0x8000u >> i) ||
						(spurs->m.wklFlag.flag.read_relaxed() == 0 &&
							spurs->m.wklFlagReceiver.read_relaxed() == (u8)i))
					{
						foundRunnableWorkload = true;
						break;
					}
				}
			}

			if (spurs->m.flags1 & SF1_32_WORKLOADS)
			{
				for (u32 i = 0; i < 16; i++)
				{
					if (spurs->m.wklState2[i].read_relaxed() == SPURS_WKL_STATE_RUNNABLE &&
						*((u64 *)spurs->m.wklInfo2[i].priority) != 0 &&
						spurs->m.wklMaxContention[i].read_relaxed() & 0xF0)
					{
						if (spurs->m.wklIdleSpuCountOrReadyCount2[i].read_relaxed() ||
							spurs->m.wklSignal2.read_relaxed() & (0x8000u >> i) ||
							(spurs->m.wklFlag.flag.read_relaxed() == 0 &&
								spurs->m.wklFlagReceiver.read_relaxed() == (u8)i + 0x10))
						{
							foundRunnableWorkload = true;
							break;
						}
					}
				}
			}

			if (foundRunnableWorkload) {
				break;
			}
		}

		// If we reach it means there are no runnable workloads in this SPURS instance.
		// Wait until some workload becomes ready.
		spurs->m.handlerWaiting.write_relaxed(1);
		if (spurs->m.handlerDirty.read_relaxed() == 0)
		{
			rc = sys_lwcond_wait(GetCurrentPPUThread(), spurs->get_lwcond(), 0);
			assert(rc == CELL_OK);
		}

		spurs->m.handlerWaiting.write_relaxed(0);
	}

	// If we reach here then a runnable workload was found
	rc = sys_lwmutex_unlock(GetCurrentPPUThread(), spurs->get_lwmutex());
	assert(rc == CELL_OK);
}

/// Entry point of the SPURS handler thread. This thread is responsible for starting the SPURS SPU thread group.
void spursHandlerEntry(PPUThread & ppu)
{
	auto spurs = vm::ptr<CellSpurs>::make(vm::cast(ppu.GPR[3]));

	try
	{
		if (spurs->m.flags & SAF_UNKNOWN_FLAG_30)
		{
			spursPpuThreadExit(0);
		}

		while (true)
		{
			if (spurs->m.flags1 & SF1_EXIT_IF_NO_WORK)
			{
				spursHandlerWaitReady(spurs);
			}

			auto rc = sys_spu_thread_group_start(spurs->m.spuTG);
			assert(rc == CELL_OK);

			rc = sys_spu_thread_group_join(spurs->m.spuTG, vm::ptr<u32>::make(0), vm::ptr<u32>::make(0));
			if (rc == CELL_ESTAT)
			{
				spursPpuThreadExit(0);
			}

			assert(rc == CELL_OK);

			if (Emu.IsStopped())
			{
				continue;
			}

			if ((spurs->m.flags1 & SF1_EXIT_IF_NO_WORK) == 0)
			{
				assert(spurs->m.handlerExiting.read_relaxed() == 1 || Emu.IsStopped());
				spursPpuThreadExit(0);
			}
		}
	}

	catch(SpursModuleExit)
	{
	}
}

/// Create the SPURS handler thread
s32 spursCreateHandler(vm::ptr<CellSpurs> spurs, u32 ppuPriority)
{
	std::string prefix(spurs->m.prefix, spurs->m.prefixSize);
	auto thread = ppu_thread_create(0/*entry*/, spurs.addr(), ppuPriority, 0x4000/*stackSize*/, true/*joinable*/, false/*isInterrupt*/, prefix + "SpursHdlr0", spursHandlerEntry);
	if (thread == nullptr)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	spurs->m.ppu0 = thread->GetId();
	return CELL_OK;
}

/// Invoke event handlers
s32 spursInvokeEventHandlers(vm::ptr<CellSpurs::EventPortMux> eventPortMux)
{
	auto reqPending = eventPortMux->reqPending.exchange(be_t<u32>::make(0)).value();
	if (reqPending)
	{
		auto & ppu         = GetCurrentPPUThread();
		auto   handlerList = eventPortMux->handlerList.exchange(be_t<u64>::make(0)).value();
		for (auto node = vm::ptr<CellSpurs::EventHandlerListNode>::make(vm::cast(handlerList)); node.addr() != 0;
			 node = vm::ptr<CellSpurs::EventHandlerListNode>::make(vm::cast(node->next)))
		{
			auto addr = vm::ptr<u32>::make(vm::cast(node->handler));
			auto toc  = vm::ptr<u32>::make(vm::cast(node->handler) + 4);

			ppu.GPR[3] = eventPortMux.addr();
			ppu.GPR[4] = node->data;
			ppu.FastCall2(*addr, *toc);
		}
	}

	return CELL_OK;
}

// Invoke workload shutdown completion callbacks
s32 spursWakeUpShutdownCompletionWaiter(vm::ptr<CellSpurs> spurs, u32 wid)
{
	if (spurs.addr() == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}

	if (wid >= (u32)(spurs->m.flags1 & SF1_32_WORKLOADS ? CELL_SPURS_MAX_WORKLOAD2 : CELL_SPURS_MAX_WORKLOAD))
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}

	if ((spurs->m.wklEnabled.read_relaxed() & (0x80000000u >> wid)) == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_SRCH;
	}

	auto wklState = wid < CELL_SPURS_MAX_WORKLOAD ? spurs->m.wklState1[wid].read_relaxed() : spurs->m.wklState2[wid & 0x0F].read_relaxed();
	if (wklState != SPURS_WKL_STATE_REMOVABLE)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}

	auto & wklF     = wid < CELL_SPURS_MAX_WORKLOAD ? spurs->m.wklF1[wid] : spurs->m.wklF2[wid & 0x0F];
	auto & wklEvent = wid < CELL_SPURS_MAX_WORKLOAD ? spurs->m.wklEvent1[wid] : spurs->m.wklEvent2[wid & 0x0F];
	if (wklF.hook.addr() != 0)
	{
		auto addr = vm::ptr<u32>::make(vm::cast(*wklF.hook));
		auto toc  = vm::ptr<u32>::make(vm::cast(*wklF.hook) + 4);

		auto & ppu = GetCurrentPPUThread();
		ppu.GPR[3] = spurs.addr();
		ppu.GPR[4] = wid;
		ppu.GPR[5] = (u32)(wid < CELL_SPURS_MAX_WORKLOAD ? spurs->m.wklF1[wid].hookArg : spurs->m.wklF2[wid & 0x0F].hookArg).addr();
		ppu.FastCall2(*addr, *toc);

		assert(wklEvent.read_relaxed() & 0x01);
		assert(wklEvent.read_relaxed() & 0x02);
		assert((wklEvent.read_relaxed() & 0x20) == 0);
		wklEvent |= 0x20;
	}

	s32 rc = CELL_OK;
	if (wklF.hook.addr() == 0 || wklEvent.read_relaxed() & 0x10)
	{
		assert(wklF.x28 == 2);
		rc = sys_semaphore_post((u32)wklF.sem, 1);
	}

	return rc;
}

/// Entry point of the SPURS event helper thread
void spursEventHelperEntry(PPUThread & ppu)
{
	auto spurs     = vm::ptr<CellSpurs>::make(vm::cast(ppu.GPR[3]));
	bool terminate = false;

	while (!terminate)
	{
		vm::var<sys_event_data> data;
		auto rc = sys_event_queue_receive(spurs->m.eventQueue, data, 0/*timeout*/);
		data->source = ppu.GPR[4];
		data->data1  = ppu.GPR[5];
		data->data2  = ppu.GPR[6];
		data->data3  = ppu.GPR[7];
		assert(rc == CELL_OK);

		if (data->source == SYS_SPU_THREAD_EVENT_EXCEPTION_KEY)
		{
			spurs->m.exception = 1;

			vm::var<sys_event_data [8]> eventArray;
			vm::var<u32>                count;
			eventArray[0] = data;
			rc = sys_event_queue_tryreceive(spurs->m.eventQueue, vm::ptr<sys_event_data>::make(eventArray.addr() + sizeof(sys_event_data)), 7, count);
			if (rc != CELL_OK)
			{
				continue;
			}

			// TODO: Examine LS and dump exception details

			for (auto i = 0; i < CELL_SPURS_MAX_WORKLOAD; i++)
			{
				sys_semaphore_post((u32)spurs->m.wklF1[i].sem, 1);
				if (spurs->m.flags1 & SF1_32_WORKLOADS)
				{
					sys_semaphore_post((u32)spurs->m.wklF2[i].sem, 1);
				}
			}
		}
		else
		{
			auto data0 = data->data2 & 0x00FFFFFF;
			if (data0 == 1)
			{
				terminate = true;
			}
			else if (data0 < 1)
			{
				auto shutdownMask = (u32)data->data3;
				for (auto wid = 0; wid < CELL_SPURS_MAX_WORKLOAD; wid++)
				{
					if (shutdownMask & (0x80000000u >> wid))
					{
						rc = spursWakeUpShutdownCompletionWaiter(spurs, wid);
						assert(rc == CELL_OK);
					}

					if ((spurs->m.flags1 & SF1_32_WORKLOADS) && (shutdownMask & (0x8000 >> wid)))
					{
						rc = spursWakeUpShutdownCompletionWaiter(spurs, wid + 0x10);
						assert(rc == CELL_OK);
					}
				}
			}
			else if (data0 == 2)
			{
				rc = sys_semaphore_post((u32)spurs->m.semPrv, 1);
				assert(rc == CELL_OK);
			}
			else if (data0 == 3)
			{
				rc = spursInvokeEventHandlers(vm::ptr<CellSpurs::EventPortMux>::make(vm::get_addr(&spurs->m.eventPortMux)));
				assert(rc == CELL_OK);
			}
			else
			{
				assert(0);
			}
		}
	}
}

/// Create the SPURS event helper thread
s32 spursCreateSpursEventHelper(vm::ptr<CellSpurs> spurs, u32 ppuPriority)
{
	vm::var<char [8]> evqName;
	memcpy(evqName, "_spuPrv", 8);
	auto rc = spursCreateLv2EventQueue(spurs, vm::ptr<u32>::make(spurs.addr() + offsetof(CellSpurs, m.eventQueue)),
									   vm::ptr<u8>::make(spurs.addr() + offsetof(CellSpurs, m.spuPort)), 0x2A/*size*/,
									   vm::ptr<const char>::make(evqName.addr()));
	if (rc != CELL_OK)
	{
		return rc;
	}

	rc = sys_event_port_create(vm::ptr<u32>::make(spurs.addr() + offsetof(CellSpurs, m.eventPort)), SYS_EVENT_PORT_LOCAL, SYS_EVENT_PORT_NO_NAME);
	if (rc != CELL_OK)
	{
		rc = spursDetachLv2EventQueue(spurs, spurs->m.spuPort, true/*spursCreated*/);
		if (rc != CELL_OK)
		{
			return CELL_SPURS_CORE_ERROR_AGAIN;
		}

		sys_event_queue_destroy(spurs->m.eventQueue, SYS_EVENT_QUEUE_DESTROY_FORCE);
		return CELL_SPURS_CORE_ERROR_AGAIN;
	}

	rc = sys_event_port_connect_local(spurs->m.eventPort, spurs->m.eventQueue);
	if (rc != CELL_OK)
	{
		sys_event_port_destroy(spurs->m.eventPort);
		rc = spursDetachLv2EventQueue(spurs, spurs->m.spuPort, true/*spursCreated*/);
		if (rc != CELL_OK)
		{
			return CELL_SPURS_CORE_ERROR_STAT;
		}

		sys_event_queue_destroy(spurs->m.eventQueue, SYS_EVENT_QUEUE_DESTROY_FORCE);
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	std::string prefix(spurs->m.prefix, spurs->m.prefixSize);
	auto thread = ppu_thread_create(0/*entry*/, spurs.addr(), ppuPriority, 0x8000/*stackSize*/, true/*joinable*/, false/*isInterrupt*/,
									prefix + "SpursHdlr1", spursEventHelperEntry);
	if (thread == nullptr)
	{
		sys_event_port_disconnect(spurs->m.eventPort);
		sys_event_port_destroy(spurs->m.eventPort);
		rc = spursDetachLv2EventQueue(spurs, spurs->m.spuPort, true/*spursCreated*/);
		if (rc != CELL_OK)
		{
			return CELL_SPURS_CORE_ERROR_STAT;
		}

		sys_event_queue_destroy(spurs->m.eventQueue, SYS_EVENT_QUEUE_DESTROY_FORCE);
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	spurs->m.ppu1 = thread->GetId();
	return CELL_OK;
}

/// Initialise the event port multiplexor structure
void spursInitialiseEventPortMux(vm::ptr<CellSpurs::EventPortMux> eventPortMux, u8 spuPort, u32 eventPort, u32 unknown)
{
	memset(eventPortMux.get_ptr(), 0, sizeof(CellSpurs::EventPortMux));
	eventPortMux->spuPort   = spuPort;
	eventPortMux->eventPort = eventPort;
	eventPortMux->x08       = unknown;
}

/// Enable the system workload
s32 spursAddDefaultSystemWorkload(vm::ptr<CellSpurs> spurs, vm::ptr<const u8> swlPriority, u32 swlMaxSpu, u32 swlIsPreem)
{
	// TODO: Implement this
	return CELL_OK;
}

/// Destroy the SPURS SPU threads and thread group
s32 spursFinalizeSpu(vm::ptr<CellSpurs> spurs)
{
	s32 rc;

	if (spurs->m.flags & SAF_UNKNOWN_FLAG_7 || spurs->m.flags & SAF_UNKNOWN_FLAG_8)
	{
		do
		{
			vm::var<u32> cause;
			vm::var<u32> status;
			rc = sys_spu_thread_group_join(spurs->m.spuTG, cause, status);
			assert(rc == CELL_OK);

			rc = sys_spu_thread_group_destroy(spurs->m.spuTG);
			if (rc == CELL_OK)
			{
				break;
			}

			assert(rc == CELL_EBUSY);
		}
		while (rc == CELL_EBUSY);
	}
	else
	{
		rc = sys_spu_thread_group_destroy(spurs->m.spuTG);
	}

	if (rc == CELL_OK)
	{
		rc = sys_spu_image_close(vm::ptr<sys_spu_image>::make(spurs.addr() + offsetof(CellSpurs, m.spuImg)));
		assert(rc == CELL_OK);
	}

	return rc;
}

/// Stop the event helper thread
s32 spursStopEventHelper(vm::ptr<CellSpurs> spurs)
{
	if (spurs->m.ppu1 == 0xFFFFFFFF)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	if (sys_event_port_send(spurs->m.eventPort, 0, 1, 0) != CELL_OK)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	vm::var<u64> exitStatus;
	if (sys_ppu_thread_join(spurs->m.ppu1, exitStatus) != CELL_OK)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	spurs->m.ppu1 = 0xFFFFFFFF;

	auto rc = sys_event_port_disconnect(spurs->m.eventPort);
	assert(rc == CELL_OK);

	rc = sys_event_port_destroy(spurs->m.eventPort);
	assert(rc == CELL_OK);

	rc = spursDetachLv2EventQueue(spurs, spurs->m.spuPort, true/*spursCreated*/);
	assert(rc == CELL_OK);

	rc = sys_event_queue_destroy(spurs->m.eventQueue, SYS_EVENT_QUEUE_DESTROY_FORCE);
	assert(rc == CELL_OK);

	return CELL_OK;
}

/// Signal to the SPURS handler thread
s32 spursSignalToHandlerThread(vm::ptr<CellSpurs> spurs)
{
	auto rc = sys_lwmutex_lock(GetCurrentPPUThread(), vm::ptr<sys_lwmutex_t>::make(spurs.addr() + offsetof(CellSpurs, m.mutex)), 0/*forever*/);
	assert(rc == CELL_OK);

	rc = sys_lwcond_signal(vm::ptr<sys_lwcond_t>::make(spurs.addr() + offsetof(CellSpurs, m.cond)));
	assert(rc == CELL_OK);

	rc = sys_lwmutex_unlock(GetCurrentPPUThread(), vm::ptr<sys_lwmutex_t>::make(spurs.addr() + offsetof(CellSpurs, m.mutex)));
	assert(rc == CELL_OK);

	return CELL_OK;
}

/// Join the SPURS handler thread
s32 spursJoinHandlerThread(vm::ptr<CellSpurs> spurs)
{
	if (spurs->m.ppu0 == 0xFFFFFFFF)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	vm::var<u64> exitStatus;
	auto rc = sys_ppu_thread_join(spurs->m.ppu0, exitStatus);
	assert(rc == CELL_OK);

	spurs->m.ppu0 = 0xFFFFFFFF;
	return CELL_OK;
}

/// Initialise SPURS
s32 spursInit(
	vm::ptr<CellSpurs> spurs,
	const u32 revision,
	const u32 sdkVersion,
	const s32 nSpus,
	const s32 spuPriority,
	const s32 ppuPriority,
	u32 flags, // SpursAttrFlags
	vm::ptr<const char> prefix,
	const u32 prefixSize,
	const u32 container,
	vm::ptr<const u8> swlPriority,
	const u32 swlMaxSpu,
	const u32 swlIsPreem)
{
	s32                                     rc = CELL_OK;
	vm::var<u32>                            sem;
	vm::var<sys_semaphore_attribute>        semAttr;
	vm::var<sys_lwcond_attribute_t>         lwCondAttr;
	vm::var<sys_lwcond_t>                   lwCond;
	vm::var<sys_lwmutex_attribute_t>        lwMutextAttr;
	vm::var<sys_lwmutex_t>                  lwMutex;
	vm::var<u32>                            spuTgId;
	vm::var<char [128]>                     spuTgName;
	vm::var<sys_spu_thread_group_attribute> spuTgAttr;
	vm::var<sys_spu_thread_argument>        spuThArgs;
	vm::var<u32>                            spuThreadId;
	vm::var<sys_spu_thread_attribute>       spuThAttr;
	vm::var<char [128]>                     spuThName;

	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (prefixSize > CELL_SPURS_NAME_MAX_LENGTH)
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	if (sys_process_is_spu_lock_line_reservation_address(spurs.addr(), SYS_MEMORY_ACCESS_RIGHT_SPU_THR) != CELL_OK)
	{
		return CELL_SPURS_CORE_ERROR_PERM;
	}

	// Intialise SPURS context
	const bool isSecond = (flags & SAF_SECOND_VERSION) != 0;
	memset(spurs.get_ptr(), 0, isSecond ? CellSpurs::size2 : CellSpurs::size1);
	spurs->m.revision   = revision;
	spurs->m.sdkVersion = sdkVersion;
	spurs->m.ppu0       = 0xffffffffull;
	spurs->m.ppu1       = 0xffffffffull;
	spurs->m.flags      = flags;
	spurs->m.prefixSize = (u8)prefixSize;
	memcpy(spurs->m.prefix, prefix.get_ptr(), prefixSize);

	if (!isSecond)
	{
		spurs->m.wklEnabled.write_relaxed(be_t<u32>::make(0xffff));
	}

	// Initialise trace
	spurs->m.xCC                  = 0;
	spurs->m.xCD                  = 0;
	spurs->m.sysSrvMsgUpdateTrace = 0;
	for (u32 i = 0; i < 8; i++)
	{
		spurs->m.sysSrvPreemptWklId[i] = -1;
	}

	// Import default system workload
	spurs->m.wklInfoSysSrv.addr.set(be_t<u64>::make(SPURS_IMG_ADDR_SYS_SRV_WORKLOAD));
	spurs->m.wklInfoSysSrv.size = 0x2200;
	spurs->m.wklInfoSysSrv.arg  = 0;
	spurs->m.wklInfoSysSrv.uniqueId.write_relaxed(0xff);

	// Create semaphores for each workload
	// TODO: Find out why these semaphores are needed
	sys_semaphore_attribute_initialize(semAttr);
	memcpy(semAttr->name, "_spuWkl", 8);
	for (u32 i = 0; i < CELL_SPURS_MAX_WORKLOAD; i++)
	{
		rc = sys_semaphore_create(sem, semAttr, 0, 1);
		if (rc != CELL_OK)
		{
			goto rollback;
		}

		spurs->m.wklF1[i].sem = sem;

		if (isSecond)
		{
			rc = sys_semaphore_create(sem, semAttr, 0, 1);
			if (rc != CELL_OK)
			{
				goto rollback;
			}

			spurs->m.wklF2[i].sem = sem;
		}
	}

	// Create semaphore
	// TODO: Figure out why this semaphore is needed
	memcpy(semAttr->name, "_spuPrv", 8);
	rc = sys_semaphore_create(sem, semAttr, 0, 1);
	if (rc != CELL_OK)
	{
		goto rollback;
	}

	spurs->m.semPrv      = sem;

	spurs->m.unk11       = -1;
	spurs->m.unk12       = -1;
	spurs->m.unk13       = 0;
	spurs->m.nSpus       = nSpus;
	spurs->m.spuPriority = spuPriority;

	// Import SPURS kernel
	spurs->m.spuImg.type        = SYS_SPU_IMAGE_TYPE_USER;
	spurs->m.spuImg.addr        = (u32)Memory.Alloc(0x40000, 4096);
	spurs->m.spuImg.entry_point = isSecond ? CELL_SPURS_KERNEL2_ENTRY_ADDR : CELL_SPURS_KERNEL1_ENTRY_ADDR;
	spurs->m.spuImg.nsegs       = 1;

	// Create a thread group for this SPURS context
	memcpy(spuTgName, spurs->m.prefix, spurs->m.prefixSize);
	spuTgName[spurs->m.prefixSize] = '\0';
	strcat(spuTgName, "CellSpursKernelGroup");

	sys_spu_thread_group_attribute_initialize(spuTgAttr);
	spuTgAttr->name  = vm::ptr<const char>::make(spuTgName.addr());
	spuTgAttr->nsize = (u32)strlen(spuTgAttr->name.get_ptr()) + 1;
	if (spurs->m.flags & SAF_UNKNOWN_FLAG_0)
	{
		spuTgAttr->type = 0x0C00 | SYS_SPU_THREAD_GROUP_TYPE_SYSTEM;
	}
	else if (flags & SAF_SPU_TGT_EXCLUSIVE_NON_CONTEXT)
	{
		spuTgAttr->type = SYS_SPU_THREAD_GROUP_TYPE_EXCLUSIVE_NON_CONTEXT;
	}
	else
	{
		spuTgAttr->type = SYS_SPU_THREAD_GROUP_TYPE_NORMAL;
	}

	if (spurs->m.flags & SAF_SPU_MEMORY_CONTAINER_SET)
	{
		spuTgAttr->type |= SYS_SPU_THREAD_GROUP_TYPE_MEMORY_FROM_CONTAINER;
		spuTgAttr->ct    = container;
	}

	if (flags & SAF_UNKNOWN_FLAG_7)          spuTgAttr->type |= 0x0100 | SYS_SPU_THREAD_GROUP_TYPE_SYSTEM;
	if (flags & SAF_UNKNOWN_FLAG_8)          spuTgAttr->type |= 0x0C00 | SYS_SPU_THREAD_GROUP_TYPE_SYSTEM;
	if (flags & SAF_UNKNOWN_FLAG_9)          spuTgAttr->type |= 0x0800;
	if (flags & SAF_SYSTEM_WORKLOAD_ENABLED) spuTgAttr->type |= SYS_SPU_THREAD_GROUP_TYPE_COOPERATE_WITH_SYSTEM;

	rc = sys_spu_thread_group_create(spuTgId, nSpus, spuPriority, spuTgAttr);
	if (rc != CELL_OK)
	{
		sys_spu_image_close(vm::ptr<sys_spu_image>::make(spurs.addr() + offsetof(CellSpurs, m.spuImg)));
		goto rollback;
	}

	spurs->m.spuTG = spuTgId;

	// Initialise all SPUs in the SPU thread group
	memcpy(spuThName, spurs->m.prefix, spurs->m.prefixSize);
	spuThName[spurs->m.prefixSize] = '\0';
	strcat(spuThName, "CellSpursKernel");

	spuThAttr->name                    = vm::ptr<const char>::make(spuThName.addr());
	spuThAttr->name_len                = (u32)strlen(spuThName) + 2;
	spuThAttr->option                  = SYS_SPU_THREAD_OPTION_DEC_SYNC_TB_ENABLE;
	spuThName[spuThAttr->name_len - 1] = '\0';

	for (s32 num = 0; num < nSpus; num++)
	{
		spuThName[spuThAttr->name_len - 2] = '0' + num;
		spuThArgs->arg1                    = (u64)num << 32;
		spuThArgs->arg2                    = spurs.addr();
		rc = sys_spu_thread_initialize(spuThreadId, spurs->m.spuTG, num, vm::ptr<sys_spu_image>::make(spurs.addr() + offsetof(CellSpurs, m.spuImg)), spuThAttr, spuThArgs);
		if (rc != CELL_OK)
		{
			sys_spu_thread_group_destroy(spurs->m.spuTG);
			sys_spu_image_close(vm::ptr<sys_spu_image>::make(spurs.addr() + offsetof(CellSpurs, m.spuImg)));
			goto rollback;
		}

		spurs->m.spus[num] = spuThreadId;
		auto spuThread     = (SPUThread*)Emu.GetCPU().GetThread(spuThreadId).get();
		spuThread->RegisterHleFunction(spurs->m.spuImg.entry_point, spursKernelEntry);
	}

	// Start the SPU printf server if required
	if (flags & SAF_SPU_PRINTF_ENABLED)
	{
		// spu_printf: attach group
		if (!spu_printf_agcb || spu_printf_agcb(spurs->m.spuTG) != CELL_OK)
		{
			// remove flag if failed
			spurs->m.flags &= ~SAF_SPU_PRINTF_ENABLED;
		}
	}

	// Create a mutex to protect access to SPURS handler thread data
	sys_lwmutex_attribute_initialize(lwMutextAttr);
	memcpy(lwMutextAttr->name, "_spuPrv", 8);
	rc = sys_lwmutex_create(GetCurrentPPUThread(), lwMutex, lwMutextAttr);
	if (rc != CELL_OK)
	{
		spursFinalizeSpu(spurs);
		goto rollback;
	}

	spurs->m.mutex = lwMutex;

	// Create condition variable to signal the SPURS handler thread
	memcpy(lwCondAttr->name, "_spuPrv", 8);
	rc = sys_lwcond_create(lwCond, lwMutex, lwCondAttr);
	if (rc != CELL_OK)
	{
		sys_lwmutex_destroy(GetCurrentPPUThread(), lwMutex);
		spursFinalizeSpu(spurs);
		goto rollback;
	}

	spurs->m.cond = lwCond;

	spurs->m.flags1 = (flags & SAF_EXIT_IF_NO_WORK ? SF1_EXIT_IF_NO_WORK : 0) | (isSecond ? SF1_32_WORKLOADS : 0);
	spurs->m.wklFlagReceiver.write_relaxed(0xff);
	spurs->m.wklFlag.flag.write_relaxed(be_t<u32>::make(-1));
	spurs->m.handlerDirty.write_relaxed(0);
	spurs->m.handlerWaiting.write_relaxed(0);
	spurs->m.handlerExiting.write_relaxed(0);
	spurs->m.ppuPriority = ppuPriority;

	// Create the SPURS event helper thread
	rc = spursCreateSpursEventHelper(spurs, ppuPriority);
	if (rc != CELL_OK)
	{
		sys_lwcond_destroy(lwCond);
		sys_lwmutex_destroy(GetCurrentPPUThread(), lwMutex);
		spursFinalizeSpu(spurs);
		goto rollback;
	}

	// Create the SPURS handler thread
	rc = spursCreateHandler(spurs, ppuPriority);
	if (rc != CELL_OK)
	{
		spursStopEventHelper(spurs);
		sys_lwcond_destroy(lwCond);
		sys_lwmutex_destroy(GetCurrentPPUThread(), lwMutex);
		spursFinalizeSpu(spurs);
		goto rollback;
	}

	// Enable SPURS exception handler
	rc = cellSpursEnableExceptionEventHandler(spurs, true/*enable*/);
	if (rc != CELL_OK)
	{
		spursSignalToHandlerThread(spurs);
		spursJoinHandlerThread(spurs);
		spursStopEventHelper(spurs);
		sys_lwcond_destroy(lwCond);
		sys_lwmutex_destroy(GetCurrentPPUThread(), lwMutex);
		spursFinalizeSpu(spurs);
		goto rollback;
	}

	spurs->m.traceBuffer.set(0);
	// TODO: Register libprof for user trace 

	// Initialise the event port multiplexor
	spursInitialiseEventPortMux(vm::ptr<CellSpurs::EventPortMux>::make(spurs.addr() + offsetof(CellSpurs, m.eventPortMux)), spurs->m.spuPort, spurs->m.eventPort, 3);

	// Enable the default system workload if required
	if (flags & SAF_SYSTEM_WORKLOAD_ENABLED)
	{
		rc = spursAddDefaultSystemWorkload(spurs, swlPriority, swlMaxSpu, swlIsPreem);
		assert(rc == CELL_OK);
	}
	else if (flags & SAF_EXIT_IF_NO_WORK)
	{
		rc = cellSpursWakeUp(GetCurrentPPUThread(), spurs);
	}

	return rc;

rollback:
	if (spurs->m.semPrv)
	{
		sys_semaphore_destroy((u32)spurs->m.semPrv);
	}

	for (u32 i = 0; i < CELL_SPURS_MAX_WORKLOAD; i++)
	{
		if (spurs->m.wklF1[i].sem)
		{
			sys_semaphore_destroy((u32)spurs->m.wklF1[i].sem);
		}

		if (isSecond)
		{
			if (spurs->m.wklF2[i].sem)
			{
				sys_semaphore_destroy((u32)spurs->m.wklF2[i].sem);
			}
		}
	}

	return rc;
}

/// Initialise SPURS
s32 cellSpursInitialize(vm::ptr<CellSpurs> spurs, s32 nSpus, s32 spuPriority, s32 ppuPriority, bool exitIfNoWork)
{
	cellSpurs.Warning("cellSpursInitialize(spurs_addr=0x%x, nSpus=%d, spuPriority=%d, ppuPriority=%d, exitIfNoWork=%d)",
		spurs.addr(), nSpus, spuPriority, ppuPriority, exitIfNoWork ? 1 : 0);

	return spursInit(
		spurs,
		0,
		0,
		nSpus,
		spuPriority,
		ppuPriority,
		exitIfNoWork ? SAF_EXIT_IF_NO_WORK : SAF_NONE,
		vm::ptr<const char>::make(0),
		0,
		0,
		vm::ptr<const u8>::make(0),
		0,
		0);
}

/// Initialise SPURS
s32 cellSpursInitializeWithAttribute(vm::ptr<CellSpurs> spurs, vm::ptr<const CellSpursAttribute> attr)
{
	cellSpurs.Warning("cellSpursInitializeWithAttribute(spurs_addr=0x%x, attr_addr=0x%x)", spurs.addr(), attr.addr());

	if (!attr)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (attr->m.revision > 2)
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}
	
	return spursInit(
		spurs,
		attr->m.revision,
		attr->m.sdkVersion,
		attr->m.nSpus,
		attr->m.spuPriority,
		attr->m.ppuPriority,
		attr->m.flags | (attr->m.exitIfNoWork ? SAF_EXIT_IF_NO_WORK : 0),
		vm::ptr<const char>::make(attr.addr() + offsetof(CellSpursAttribute, m.prefix)),
		attr->m.prefixSize,
		attr->m.container,
		vm::ptr<const u8>::make(attr.addr() + offsetof(CellSpursAttribute, m.swlPriority)),
		attr->m.swlMaxSpu,
		attr->m.swlIsPreem);
}

/// Initialise SPURS
s32 cellSpursInitializeWithAttribute2(vm::ptr<CellSpurs> spurs, vm::ptr<const CellSpursAttribute> attr)
{
	cellSpurs.Warning("cellSpursInitializeWithAttribute2(spurs_addr=0x%x, attr_addr=0x%x)", spurs.addr(), attr.addr());

	if (!attr)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (attr->m.revision > 2)
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	return spursInit(
		spurs,
		attr->m.revision,
		attr->m.sdkVersion,
		attr->m.nSpus,
		attr->m.spuPriority,
		attr->m.ppuPriority,
		attr->m.flags | (attr->m.exitIfNoWork ? SAF_EXIT_IF_NO_WORK : 0) | SAF_SECOND_VERSION,
		vm::ptr<const char>::make(attr.addr() + offsetof(CellSpursAttribute, m.prefix)),
		attr->m.prefixSize,
		attr->m.container,
		vm::ptr<const u8>::make(attr.addr() + offsetof(CellSpursAttribute, m.swlPriority)),
		attr->m.swlMaxSpu,
		attr->m.swlIsPreem);
}

/// Initialise SPURS attribute
s32 _cellSpursAttributeInitialize(vm::ptr<CellSpursAttribute> attr, u32 revision, u32 sdkVersion, u32 nSpus, s32 spuPriority, s32 ppuPriority, bool exitIfNoWork)
{
	cellSpurs.Warning("_cellSpursAttributeInitialize(attr_addr=0x%x, revision=%d, sdkVersion=0x%x, nSpus=%d, spuPriority=%d, ppuPriority=%d, exitIfNoWork=%d)",
		attr.addr(), revision, sdkVersion, nSpus, spuPriority, ppuPriority, exitIfNoWork ? 1 : 0);

	if (!attr)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	memset(attr.get_ptr(), 0, attr->size);
	attr->m.revision     = revision;
	attr->m.sdkVersion   = sdkVersion;
	attr->m.nSpus        = nSpus;
	attr->m.spuPriority  = spuPriority;
	attr->m.ppuPriority  = ppuPriority;
	attr->m.exitIfNoWork = exitIfNoWork;
	return CELL_OK;
}

/// Set memory container ID for creating the SPU thread group
s32 cellSpursAttributeSetMemoryContainerForSpuThread(vm::ptr<CellSpursAttribute> attr, u32 container)
{
	cellSpurs.Warning("cellSpursAttributeSetMemoryContainerForSpuThread(attr_addr=0x%x, container=%d)", attr.addr(), container);

	if (!attr)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (attr->m.flags & SAF_SPU_TGT_EXCLUSIVE_NON_CONTEXT)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	attr->m.container  = container;
	attr->m.flags     |= SAF_SPU_MEMORY_CONTAINER_SET;
	return CELL_OK;
}

/// Set the prefix for SPURS
s32 cellSpursAttributeSetNamePrefix(vm::ptr<CellSpursAttribute> attr, vm::ptr<const char> prefix, u32 size)
{
	cellSpurs.Warning("cellSpursAttributeSetNamePrefix(attr_addr=0x%x, prefix_addr=0x%x, size=%d)", attr.addr(), prefix.addr(), size);

	if (!attr || !prefix)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (size > CELL_SPURS_NAME_MAX_LENGTH)
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	memcpy(attr->m.prefix, prefix.get_ptr(), size);
	attr->m.prefixSize = size;
	return CELL_OK;
}

/// Enable spu_printf()
s32 cellSpursAttributeEnableSpuPrintfIfAvailable(vm::ptr<CellSpursAttribute> attr)
{
	cellSpurs.Warning("cellSpursAttributeEnableSpuPrintfIfAvailable(attr_addr=0x%x)", attr.addr());

	if (!attr)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	attr->m.flags |= SAF_SPU_PRINTF_ENABLED;
	return CELL_OK;
}

/// Set the type of SPU thread group
s32 cellSpursAttributeSetSpuThreadGroupType(vm::ptr<CellSpursAttribute> attr, s32 type)
{
	cellSpurs.Warning("cellSpursAttributeSetSpuThreadGroupType(attr_addr=0x%x, type=%d)", attr.addr(), type);

	if (!attr)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (type == SYS_SPU_THREAD_GROUP_TYPE_EXCLUSIVE_NON_CONTEXT)
	{
		if (attr->m.flags & SAF_SPU_MEMORY_CONTAINER_SET)
		{
			return CELL_SPURS_CORE_ERROR_STAT;
		}
		attr->m.flags |= SAF_SPU_TGT_EXCLUSIVE_NON_CONTEXT; // set
	}
	else if (type == SYS_SPU_THREAD_GROUP_TYPE_NORMAL)
	{
		attr->m.flags &= ~SAF_SPU_TGT_EXCLUSIVE_NON_CONTEXT; // clear
	}
	else
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	return CELL_OK;
}

/// Enable the system workload
s32 cellSpursAttributeEnableSystemWorkload(vm::ptr<CellSpursAttribute> attr, vm::ptr<const u8[8]> priority, u32 maxSpu, vm::ptr<const bool[8]> isPreemptible)
{
	cellSpurs.Warning("cellSpursAttributeEnableSystemWorkload(attr_addr=0x%x, priority_addr=0x%x, maxSpu=%d, isPreemptible_addr=0x%x)",
		attr.addr(), priority.addr(), maxSpu, isPreemptible.addr());

	if (!attr)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursAttribute::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (attr->m.nSpus == 0)
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	for (u32 i = 0; i < attr->m.nSpus; i++)
	{
		if ((*priority)[i] == 1)
		{
			if (!maxSpu)
			{
				return CELL_SPURS_CORE_ERROR_INVAL;
			}

			if (attr->m.nSpus == 1 || attr->m.exitIfNoWork)
			{
				return CELL_SPURS_CORE_ERROR_PERM;
			}

			if (attr->m.flags & SAF_SYSTEM_WORKLOAD_ENABLED)
			{
				return CELL_SPURS_CORE_ERROR_BUSY;
			}

			attr->m.flags |= SAF_SYSTEM_WORKLOAD_ENABLED; // set flag
			*(u64*)attr->m.swlPriority = *(u64*)*priority; // copy system workload priorities

			u32 isPreem = 0; // generate mask from isPreemptible values
			for (u32 j = 0; j < attr->m.nSpus; j++)
			{
				if ((*isPreemptible)[j])
				{
					isPreem |= (1 << j);
				}
			}
			attr->m.swlMaxSpu  = maxSpu;  // write max spu for system workload
			attr->m.swlIsPreem = isPreem; // write isPreemptible mask
			return CELL_OK;
		}
	}

	return CELL_SPURS_CORE_ERROR_INVAL;
}

/// Release resources allocated for SPURS
s32 cellSpursFinalize(vm::ptr<CellSpurs> spurs)
{
	cellSpurs.Todo("cellSpursFinalize(spurs_addr=0x%x)", spurs.addr());

	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (spurs->m.handlerExiting.read_relaxed())
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	auto wklEnabled = spurs->m.wklEnabled.read_relaxed().value();
	if (spurs->m.flags1 & SF1_32_WORKLOADS)
	{
		wklEnabled &= 0xFFFF0000;
	}

	if (spurs->m.flags & SAF_SYSTEM_WORKLOAD_ENABLED)
	{
	}

	// TODO: Implement the rest of this function
	return CELL_OK;
}

/// Get the SPU thread group ID
s32 cellSpursGetSpuThreadGroupId(vm::ptr<CellSpurs> spurs, vm::ptr<u32> group)
{
	cellSpurs.Warning("cellSpursGetSpuThreadGroupId(spurs_addr=0x%x, group_addr=0x%x)", spurs.addr(), group.addr());

	if (!spurs || !group)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	*group = spurs->m.spuTG;
	return CELL_OK;
}

// Get the number of SPU threads
s32 cellSpursGetNumSpuThread(vm::ptr<CellSpurs> spurs, vm::ptr<u32> nThreads)
{
	cellSpurs.Warning("cellSpursGetNumSpuThread(spurs_addr=0x%x, nThreads_addr=0x%x)", spurs.addr(), nThreads.addr());

	if (!spurs || !nThreads)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	*nThreads = (u32)spurs->m.nSpus;
	return CELL_OK;
}

/// Get SPU thread ids
s32 cellSpursGetSpuThreadId(vm::ptr<CellSpurs> spurs, vm::ptr<u32> thread, vm::ptr<u32> nThreads)
{
	cellSpurs.Warning("cellSpursGetSpuThreadId(spurs_addr=0x%x, thread_addr=0x%x, nThreads_addr=0x%x)", spurs.addr(), thread.addr(), nThreads.addr());

	if (!spurs || !thread || !nThreads)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	const u32 count = std::min<u32>(*nThreads, spurs->m.nSpus);
	for (u32 i = 0; i < count; i++)
	{
		thread[i] = spurs->m.spus[i];
	}

	*nThreads = count;
	return CELL_OK;
}

/// Set the maximum contention for a workload
s32 cellSpursSetMaxContention(vm::ptr<CellSpurs> spurs, u32 workloadId, u32 maxContention)
{
	cellSpurs.Warning("cellSpursSetMaxContention(spurs_addr=0x%x, workloadId=%d, maxContention=%d)", spurs.addr(), workloadId, maxContention);

	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (workloadId >= (spurs->m.flags1 & SF1_32_WORKLOADS ? CELL_SPURS_MAX_WORKLOAD2 : CELL_SPURS_MAX_WORKLOAD))
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	if ((spurs->m.wklEnabled.read_relaxed() & (0x80000000u >> workloadId)) == 0)
	{
		return CELL_SPURS_CORE_ERROR_SRCH;
	}

	if (spurs->m.exception)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	maxContention = maxContention > CELL_SPURS_MAX_SPU ? CELL_SPURS_MAX_SPU : maxContention;
	spurs->m.wklMaxContention[workloadId % CELL_SPURS_MAX_WORKLOAD].atomic_op([spurs, workloadId, maxContention](u8 & value)
	{
		value &= workloadId < CELL_SPURS_MAX_WORKLOAD ? 0xF0 : 0x0F;
		value |= workloadId < CELL_SPURS_MAX_WORKLOAD ? maxContention : maxContention << 4;
	});

	return CELL_OK;
}

/// Set the priority of a workload on each SPU
s32 cellSpursSetPriorities(vm::ptr<CellSpurs> spurs, u32 workloadId, vm::ptr<const u8> priorities)
{
	cellSpurs.Warning("cellSpursSetPriorities(spurs_addr=0x%x, workloadId=%d, priorities_addr=0x%x)", spurs.addr(), workloadId, priorities.addr());

	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (workloadId >= (spurs->m.flags1 & SF1_32_WORKLOADS ? CELL_SPURS_MAX_WORKLOAD2 : CELL_SPURS_MAX_WORKLOAD))
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	if ((spurs->m.wklEnabled.read_relaxed() & (0x80000000u >> workloadId)) == 0)
	{
		return CELL_SPURS_CORE_ERROR_SRCH;
	}

	if (spurs->m.exception)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	if (spurs->m.flags & SAF_SYSTEM_WORKLOAD_ENABLED)
	{
		// TODO: Implement this
	}

	u64 prio = 0;
	for (int i = 0; i < CELL_SPURS_MAX_SPU; i++)
	{
		if (priorities[i] >= CELL_SPURS_MAX_PRIORITY)
		{
			return CELL_SPURS_CORE_ERROR_INVAL;
		}

		prio |=  priorities[i];
		prio <<= 8;
	}

	auto & wklInfo   = workloadId < CELL_SPURS_MAX_WORKLOAD ? spurs->m.wklInfo1[workloadId] : spurs->m.wklInfo2[workloadId];
	*((be_t<u64> *)wklInfo.priority) = prio;

	spurs->m.sysSrvMsgUpdateWorkload.write_relaxed(0xFF);
	spurs->m.sysSrvMessage.write_relaxed(0xFF);
	return CELL_OK;
}

/// Set preemption victim SPU
s32 cellSpursSetPreemptionVictimHints(vm::ptr<CellSpurs> spurs, vm::ptr<const bool> isPreemptible)
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

/// Attach an LV2 event queue to a SPURS instance
s32 cellSpursAttachLv2EventQueue(vm::ptr<CellSpurs> spurs, u32 queue, vm::ptr<u8> port, s32 isDynamic)
{
	cellSpurs.Warning("cellSpursAttachLv2EventQueue(spurs_addr=0x%x, queue=%d, port_addr=0x%x, isDynamic=%d)",
		spurs.addr(), queue, port.addr(), isDynamic);

	return spursAttachLv2EventQueue(spurs, queue, port, isDynamic, false/*spursCreated*/);
}

/// Detach an LV2 event queue from a SPURS instance
s32 cellSpursDetachLv2EventQueue(vm::ptr<CellSpurs> spurs, u8 port)
{
	cellSpurs.Warning("cellSpursDetachLv2EventQueue(spurs_addr=0x%x, port=%d)", spurs.addr(), port);

	return spursDetachLv2EventQueue(spurs, port, false/*spursCreated*/);
}

/// Enable the SPU exception event handler
s32 cellSpursEnableExceptionEventHandler(vm::ptr<CellSpurs> spurs, bool flag)
{
	cellSpurs.Warning("cellSpursEnableExceptionEventHandler(spurs_addr=0x%x, flag=%d)", spurs.addr(), flag);

	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	s32  rc          = CELL_OK;
	auto oldEnableEH = spurs->m.enableEH.exchange(be_t<u32>::make(flag ? 1u : 0u));
	if (flag)
	{
		if (oldEnableEH == 0)
		{
			rc = sys_spu_thread_group_connect_event(spurs->m.spuTG, spurs->m.eventQueue, SYS_SPU_THREAD_GROUP_EVENT_EXCEPTION);
		}
	}
	else
	{
		if (oldEnableEH == 1)
		{
			rc = sys_spu_thread_group_disconnect_event(spurs->m.eventQueue, SYS_SPU_THREAD_GROUP_EVENT_EXCEPTION);
		}
	}

	return rc;
}

/// Set the global SPU exception event handler
s32 cellSpursSetGlobalExceptionEventHandler(vm::ptr<CellSpurs> spurs, vm::ptr<void> eaHandler, vm::ptr<void> arg)
{
	cellSpurs.Warning("cellSpursSetGlobalExceptionEventHandler(spurs_addr=0x%x, eaHandler_addr=0x%x, arg_addr=0x%x)", spurs.addr(), eaHandler.addr(), arg.addr());

	if (!spurs || !eaHandler)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (spurs->m.exception)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	auto handler = spurs->m.globalSpuExceptionHandler.compare_and_swap(be_t<u64>::make(0), be_t<u64>::make(1));
	if (handler)
	{
		return CELL_SPURS_CORE_ERROR_BUSY;
	}

	spurs->m.globalSpuExceptionHandlerArgs = arg.addr();
	spurs->m.globalSpuExceptionHandler.exchange(be_t<u64>::make(eaHandler.addr()));
	return CELL_OK;
}


/// Remove the global SPU exception event handler
s32 cellSpursUnsetGlobalExceptionEventHandler(vm::ptr<CellSpurs> spurs)
{
	cellSpurs.Warning("cellSpursUnsetGlobalExceptionEventHandler(spurs_addr=0x%x)", spurs.addr());

	spurs->m.globalSpuExceptionHandlerArgs = 0;
	spurs->m.globalSpuExceptionHandler.exchange(be_t<u64>::make(0));
	return CELL_OK;
}

/// Get internal information of a SPURS instance
s32 cellSpursGetInfo(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursInfo> info)
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

//----------------------------------------------------------------------------
// SPURS SPU GUID functions
//----------------------------------------------------------------------------

/// Get the SPU GUID from a .SpuGUID section
s32 cellSpursGetSpuGuid()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

//----------------------------------------------------------------------------
// SPURS trace functions
//----------------------------------------------------------------------------

void spursTraceStatusUpdate(vm::ptr<CellSpurs> spurs)
{
	LV2_LOCK(0);

	if (spurs->m.xCC != 0)
	{
		spurs->m.xCD                  = 1;
		spurs->m.sysSrvMsgUpdateTrace = (1 << spurs->m.nSpus) - 1;
		spurs->m.sysSrvMessage.write_relaxed(0xFF);
		sys_semaphore_wait((u32)spurs->m.semPrv, 0);
	}
}

s32 spursTraceInitialize(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTraceInfo> buffer, u32 size, u32 mode, u32 updateStatus)
{
	if (!spurs || !buffer)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align || buffer.addr() % CellSpursTraceInfo::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (size < CellSpursTraceInfo::size || mode & ~(CELL_SPURS_TRACE_MODE_FLAG_MASK))
	{
		return CELL_SPURS_CORE_ERROR_INVAL;
	}

	if (spurs->m.traceBuffer != 0)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	spurs->m.traceDataSize = size - CellSpursTraceInfo::size;
	for (u32 i = 0; i < 8; i++)
	{
		buffer->spuThread[i] = spurs->m.spus[i];
		buffer->count[i]     = 0;
	}

	buffer->spuThreadGroup = spurs->m.spuTG;
	buffer->numSpus        = spurs->m.nSpus;
	spurs->m.traceBuffer.set(buffer.addr() | (mode & CELL_SPURS_TRACE_MODE_FLAG_WRAP_BUFFER ? 1 : 0));
	spurs->m.traceMode     = mode;

	u32 spuTraceDataCount = (u32)((spurs->m.traceDataSize / CellSpursTracePacket::size) / spurs->m.nSpus);
	for (u32 i = 0, j = 8; i < 6; i++)
	{
		spurs->m.traceStartIndex[i] = j;
		j += spuTraceDataCount;
	}

	spurs->m.sysSrvTraceControl = 0;
	if (updateStatus)
	{
		spursTraceStatusUpdate(spurs);
	}

	return CELL_OK;
}

s32 cellSpursTraceInitialize(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTraceInfo> buffer, u32 size, u32 mode)
{
	if (spursIsLibProfLoaded())
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	return spursTraceInitialize(spurs, buffer, size, mode, 1);
}

s32 cellSpursTraceFinalize(vm::ptr<CellSpurs> spurs)
{
	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (!spurs->m.traceBuffer)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	spurs->m.sysSrvTraceControl = 0;
	spurs->m.traceMode          = 0;
	spurs->m.traceBuffer.set(0);
	spursTraceStatusUpdate(spurs);
	return CELL_OK;
}

s32 spursTraceStart(vm::ptr<CellSpurs> spurs, u32 updateStatus)
{
	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (!spurs->m.traceBuffer)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	spurs->m.sysSrvTraceControl = 1;
	if (updateStatus)
	{
		spursTraceStatusUpdate(spurs);
	}

	return CELL_OK;
}

s32 cellSpursTraceStart(vm::ptr<CellSpurs> spurs)
{
	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	return spursTraceStart(spurs, spurs->m.traceMode & CELL_SPURS_TRACE_MODE_FLAG_SYNCHRONOUS_START_STOP);
}

s32 spursTraceStop(vm::ptr<CellSpurs> spurs, u32 updateStatus)
{
	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	if (!spurs->m.traceBuffer)
	{
		return CELL_SPURS_CORE_ERROR_STAT;
	}

	spurs->m.sysSrvTraceControl = 2;
	if (updateStatus)
	{
		spursTraceStatusUpdate(spurs);
	}

	return CELL_OK;
}

s32 cellSpursTraceStop(vm::ptr<CellSpurs> spurs)
{
	if (!spurs)
	{
		return CELL_SPURS_CORE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_CORE_ERROR_ALIGN;
	}

	return spursTraceStop(spurs, spurs->m.traceMode & CELL_SPURS_TRACE_MODE_FLAG_SYNCHRONOUS_START_STOP);
}

s32 spursWakeUp(PPUThread& CPU, vm::ptr<CellSpurs> spurs)
{
	if (!spurs)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (spurs.addr() % 128)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}
	if (spurs->m.exception.data())
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}

	spurs->m.handlerDirty.exchange(1);
	if (spurs->m.handlerWaiting.read_sync())
	{
		if (s32 res = sys_lwmutex_lock(CPU, spurs->get_lwmutex(), 0))
		{
			assert(!"sys_lwmutex_lock() failed");
		}
		if (s32 res = sys_lwcond_signal(spurs->get_lwcond()))
		{
			assert(!"sys_lwcond_signal() failed");
		}
		if (s32 res = sys_lwmutex_unlock(CPU, spurs->get_lwmutex()))
		{
			assert(!"sys_lwmutex_unlock() failed");
		}
	}
	return CELL_OK;
}

s32 cellSpursWakeUp(PPUThread& CPU, vm::ptr<CellSpurs> spurs)
{
	cellSpurs.Warning("%s(spurs_addr=0x%x)", __FUNCTION__, spurs.addr());

	return spursWakeUp(CPU, spurs);
}

s32 spursAddWorkload(
	vm::ptr<CellSpurs> spurs,
	vm::ptr<u32> wid,
	vm::ptr<const void> pm,
	u32 size,
	u64 data,
	const u8 priorityTable[],
	u32 minContention,
	u32 maxContention,
	vm::ptr<const char> nameClass,
	vm::ptr<const char> nameInstance,
	vm::ptr<u64> hook,
	vm::ptr<void> hookArg)
{
	if (!spurs || !wid || !pm)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (spurs.addr() % 128 || pm.addr() % 16)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}
	if (minContention == 0 || *(u64*)priorityTable & 0xf0f0f0f0f0f0f0f0ull) // check if some priority > 15
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}
	if (spurs->m.exception.data())
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}
	
	u32 wnum;
	const u32 wmax = spurs->m.flags1 & SF1_32_WORKLOADS ? 0x20u : 0x10u; // TODO: check if can be changed
	spurs->m.wklEnabled.atomic_op([spurs, wmax, &wnum](be_t<u32>& value)
	{
		wnum = cntlz32(~(u32)value); // found empty position
		if (wnum < wmax)
		{
			value |= (u32)(0x80000000ull >> wnum); // set workload bit
		}
	});

	*wid = wnum; // store workload id
	if (wnum >= wmax)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_AGAIN;
	}

	u32 index = wnum & 0xf;
	if (wnum <= 15)
	{
		assert((spurs->m.wklCurrentContention[wnum] & 0xf) == 0);
		assert((spurs->m.wklPendingContention[wnum] & 0xf) == 0);
		spurs->m.wklState1[wnum].write_relaxed(1);
		spurs->m.wklStatus1[wnum] = 0;
		spurs->m.wklEvent1[wnum].write_relaxed(0);
		spurs->m.wklInfo1[wnum].addr = pm;
		spurs->m.wklInfo1[wnum].arg = data;
		spurs->m.wklInfo1[wnum].size = size;
		for (u32 i = 0; i < 8; i++)
		{
			spurs->m.wklInfo1[wnum].priority[i] = priorityTable[i];
		}
		spurs->m.wklH1[wnum].nameClass = nameClass;
		spurs->m.wklH1[wnum].nameInstance = nameInstance;
		memset(spurs->m.wklF1[wnum].unk0, 0, 0x20); // clear struct preserving semaphore id
		memset(&spurs->m.wklF1[wnum].x28, 0, 0x58);
		if (hook)
		{
			spurs->m.wklF1[wnum].hook = hook;
			spurs->m.wklF1[wnum].hookArg = hookArg;
			spurs->m.wklEvent1[wnum] |= 2;
		}
		if ((spurs->m.flags1 & SF1_32_WORKLOADS) == 0)
		{
			spurs->m.wklIdleSpuCountOrReadyCount2[wnum].write_relaxed(0);
			spurs->m.wklMinContention[wnum] = minContention > 8 ? 8 : minContention;
		}
		spurs->m.wklReadyCount1[wnum].write_relaxed(0);
	}
	else
	{
		assert((spurs->m.wklCurrentContention[index] & 0xf0) == 0);
		assert((spurs->m.wklPendingContention[index] & 0xf0) == 0);
		spurs->m.wklState2[index].write_relaxed(1);
		spurs->m.wklStatus2[index] = 0;
		spurs->m.wklEvent2[index].write_relaxed(0);
		spurs->m.wklInfo2[index].addr = pm;
		spurs->m.wklInfo2[index].arg = data;
		spurs->m.wklInfo2[index].size = size;
		for (u32 i = 0; i < 8; i++)
		{
			spurs->m.wklInfo2[index].priority[i] = priorityTable[i];
		}
		spurs->m.wklH2[index].nameClass = nameClass;
		spurs->m.wklH2[index].nameInstance = nameInstance;
		memset(spurs->m.wklF2[index].unk0, 0, 0x20); // clear struct preserving semaphore id
		memset(&spurs->m.wklF2[index].x28, 0, 0x58);
		if (hook)
		{
			spurs->m.wklF2[index].hook = hook;
			spurs->m.wklF2[index].hookArg = hookArg;
			spurs->m.wklEvent2[index] |= 2;
		}
		spurs->m.wklIdleSpuCountOrReadyCount2[wnum].write_relaxed(0);
	}

	if (wnum <= 15)
	{
		spurs->m.wklMaxContention[wnum].atomic_op([maxContention](u8& v)
		{
			v &= ~0xf;
			v |= (maxContention > 8 ? 8 : maxContention);
		});
		spurs->m.wklSignal1._and_not({ be_t<u16>::make(0x8000 >> index) }); // clear bit in wklFlag1
	}
	else
	{
		spurs->m.wklMaxContention[index].atomic_op([maxContention](u8& v)
		{
			v &= ~0xf0;
			v |= (maxContention > 8 ? 8 : maxContention) << 4;
		});
		spurs->m.wklSignal2._and_not({ be_t<u16>::make(0x8000 >> index) }); // clear bit in wklFlag2
	}

	spurs->m.wklFlagReceiver.compare_and_swap(wnum, 0xff);

	u32 res_wkl;
	CellSpurs::WorkloadInfo& wkl = wnum <= 15 ? spurs->m.wklInfo1[wnum] : spurs->m.wklInfo2[wnum & 0xf];
	spurs->m.wklMskB.atomic_op_sync([spurs, &wkl, wnum, &res_wkl](be_t<u32>& v)
	{
		const u32 mask = v & ~(0x80000000u >> wnum);
		res_wkl = 0;

		for (u32 i = 0, m = 0x80000000, k = 0; i < 32; i++, m >>= 1)
		{
			if (mask & m)
			{
				CellSpurs::WorkloadInfo& current = i <= 15 ? spurs->m.wklInfo1[i] : spurs->m.wklInfo2[i & 0xf];
				if (current.addr.addr() == wkl.addr.addr())
				{
					// if a workload with identical policy module found
					res_wkl = current.uniqueId.read_relaxed();
					break;
				}
				else
				{
					k |= 0x80000000 >> current.uniqueId.read_relaxed();
					res_wkl = cntlz32(~k);
				}
			}
		}

		wkl.uniqueId.exchange((u8)res_wkl);
		v = mask | (0x80000000u >> wnum);
	});
	assert(res_wkl <= 31);

	spurs->wklState(wnum).exchange(2);
	spurs->m.sysSrvMsgUpdateWorkload.exchange(0xff);
	spurs->m.sysSrvMessage.exchange(0xff);
	return CELL_OK;
}

s32 cellSpursAddWorkload(
	vm::ptr<CellSpurs> spurs,
	vm::ptr<u32> wid,
	vm::ptr<const void> pm,
	u32 size,
	u64 data,
	vm::ptr<const u8[8]> priorityTable,
	u32 minContention,
	u32 maxContention)
{
	cellSpurs.Warning("%s(spurs_addr=0x%x, wid_addr=0x%x, pm_addr=0x%x, size=0x%x, data=0x%llx, priorityTable_addr=0x%x, minContention=0x%x, maxContention=0x%x)",
		__FUNCTION__, spurs.addr(), wid.addr(), pm.addr(), size, data, priorityTable.addr(), minContention, maxContention);

	return spursAddWorkload(
		spurs,
		wid,
		pm,
		size,
		data,
		*priorityTable,
		minContention,
		maxContention,
		vm::ptr<const char>::make(0),
		vm::ptr<const char>::make(0),
		vm::ptr<u64>::make(0),
		vm::ptr<void>::make(0));
}

s32 _cellSpursWorkloadAttributeInitialize(
	vm::ptr<CellSpursWorkloadAttribute> attr,
	u32 revision,
	u32 sdkVersion,
	vm::ptr<const void> pm,
	u32 size,
	u64 data,
	vm::ptr<const u8[8]> priorityTable,
	u32 minContention,
	u32 maxContention)
{
	cellSpurs.Warning("%s(attr_addr=0x%x, revision=%d, sdkVersion=0x%x, pm_addr=0x%x, size=0x%x, data=0x%llx, priorityTable_addr=0x%x, minContention=0x%x, maxContention=0x%x)",
		__FUNCTION__, attr.addr(), revision, sdkVersion, pm.addr(), size, data, priorityTable.addr(), minContention, maxContention);

	if (!attr)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (attr.addr() % 8)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}
	if (!pm)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (pm.addr() % 16)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}
	if (minContention == 0 || *(u64*)*priorityTable & 0xf0f0f0f0f0f0f0f0ull) // check if some priority > 15
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}
	
	memset(attr.get_ptr(), 0, CellSpursWorkloadAttribute::size);
	attr->m.revision = revision;
	attr->m.sdkVersion = sdkVersion;
	attr->m.pm = pm;
	attr->m.size = size;
	attr->m.data = data;
	*(u64*)attr->m.priority = *(u64*)*priorityTable;
	attr->m.minContention = minContention;
	attr->m.maxContention = maxContention;
	return CELL_OK;
}

s32 cellSpursWorkloadAttributeSetName(vm::ptr<CellSpursWorkloadAttribute> attr, vm::ptr<const char> nameClass, vm::ptr<const char> nameInstance)
{
	cellSpurs.Warning("%s(attr_addr=0x%x, nameClass_addr=0x%x, nameInstance_addr=0x%x)", __FUNCTION__, attr.addr(), nameClass.addr(), nameInstance.addr());

	if (!attr)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (attr.addr() % 8)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}

	attr->m.nameClass = nameClass;
	attr->m.nameInstance = nameInstance;
	return CELL_OK;
}

s32 cellSpursWorkloadAttributeSetShutdownCompletionEventHook(vm::ptr<CellSpursWorkloadAttribute> attr, vm::ptr<CellSpursShutdownCompletionEventHook> hook, vm::ptr<void> arg)
{
	cellSpurs.Warning("%s(attr_addr=0x%x, hook_addr=0x%x, arg=0x%x)", __FUNCTION__, attr.addr(), hook.addr(), arg.addr());

	if (!attr || !hook)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (attr.addr() % 8)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}

	attr->m.hook = hook;
	attr->m.hookArg = arg;
	return CELL_OK;
}

s32 cellSpursAddWorkloadWithAttribute(vm::ptr<CellSpurs> spurs, const vm::ptr<u32> wid, vm::ptr<const CellSpursWorkloadAttribute> attr)
{
	cellSpurs.Warning("%s(spurs_addr=0x%x, wid_addr=0x%x, attr_addr=0x%x)", __FUNCTION__, spurs.addr(), wid.addr(), attr.addr());

	if (!attr)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (attr.addr() % 8)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}
	if (attr->m.revision != be_t<u32>::make(1))
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}

	return spursAddWorkload(
		spurs,
		wid,
		vm::ptr<const void>::make(attr->m.pm.addr()),
		attr->m.size,
		attr->m.data,
		attr->m.priority,
		attr->m.minContention,
		attr->m.maxContention,
		vm::ptr<const char>::make(attr->m.nameClass.addr()),
		vm::ptr<const char>::make(attr->m.nameInstance.addr()),
		vm::ptr<u64>::make(attr->m.hook.addr()),
		vm::ptr<void>::make(attr->m.hookArg.addr()));
}

s32 cellSpursRemoveWorkload()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursWaitForWorkloadShutdown()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursShutdownWorkload()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursWorkloadFlagReceiver(vm::ptr<CellSpurs> spurs, u32 wid, u32 is_set)
{
	cellSpurs.Warning("%s(spurs_addr=0x%x, wid=%d, is_set=%d)", __FUNCTION__, spurs.addr(), wid, is_set);

	if (!spurs)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (spurs.addr() % 128)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}
	if (wid >= (spurs->m.flags1 & SF1_32_WORKLOADS ? 0x20u : 0x10u))
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}
	if ((spurs->m.wklEnabled.read_relaxed() & (0x80000000u >> wid)) == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_SRCH;
	}
	if (spurs->m.exception.data())
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}
	if (s32 res = spurs->m.wklFlag.flag.atomic_op_sync(0, [spurs, wid, is_set](be_t<u32>& flag) -> s32
	{
		if (is_set)
		{
			if (spurs->m.wklFlagReceiver.read_relaxed() != 0xff)
			{
				return CELL_SPURS_POLICY_MODULE_ERROR_BUSY;
			}
		}
		else
		{
			if (spurs->m.wklFlagReceiver.read_relaxed() != wid)
			{
				return CELL_SPURS_POLICY_MODULE_ERROR_PERM;
			}
		}
		flag = -1;
		return 0;
	}))
	{
		return res;
	}

	spurs->m.wklFlagReceiver.atomic_op([wid, is_set](u8& FR)
	{
		if (is_set)
		{
			if (FR == 0xff)
			{
				FR = (u8)wid;
			}
		}
		else
		{
			if (FR == wid)
			{
				FR = 0xff;
			}
		}
	});
	return CELL_OK;
}

s32 cellSpursGetWorkloadFlag(vm::ptr<CellSpurs> spurs, vm::ptr<vm::bptr<CellSpursWorkloadFlag>> flag)
{
	cellSpurs.Warning("%s(spurs_addr=0x%x, flag_addr=0x%x)", __FUNCTION__, spurs.addr(), flag.addr());

	if (!spurs || !flag)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (spurs.addr() % 128)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}

	flag->set(vm::get_addr(&spurs->m.wklFlag));
	return CELL_OK;
}

s32 cellSpursSendWorkloadSignal(vm::ptr<CellSpurs> spurs, u32 workloadId)
{
	cellSpurs.Warning("%s(spurs=0x%x, workloadId=0x%x)", __FUNCTION__, spurs.addr(), workloadId);

	if (spurs.addr() == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}

	if (workloadId >= CELL_SPURS_MAX_WORKLOAD2 || (workloadId >= CELL_SPURS_MAX_WORKLOAD && (spurs->m.flags1 & SF1_32_WORKLOADS) == 0))
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}

	if ((spurs->m.wklEnabled.read_relaxed() & (0x80000000u >> workloadId)) == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_SRCH;
	}

	if (spurs->m.exception)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}

	u8 state;
	if (workloadId >= CELL_SPURS_MAX_WORKLOAD)
	{
		state = spurs->m.wklState2[workloadId & 0x0F].read_relaxed();
	}
	else
	{
		state = spurs->m.wklState1[workloadId].read_relaxed();
	}

	if (state != SPURS_WKL_STATE_RUNNABLE)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}

	if (workloadId >= CELL_SPURS_MAX_WORKLOAD)
	{
		spurs->m.wklSignal2 |= be_t<u16>::make(0x8000 >> (workloadId & 0x0F));
	}
	else
	{
		spurs->m.wklSignal1 |= be_t<u16>::make(0x8000 >> workloadId);
	}

	return CELL_OK;
}

s32 cellSpursGetWorkloadData(vm::ptr<CellSpurs> spurs, vm::ptr<u64> data, u32 workloadId)
{
	cellSpurs.Warning("%s(spurs_addr=0x%x, data=0x%x, workloadId=%d)", __FUNCTION__, spurs.addr(), data.addr(), workloadId);

	if (spurs.addr() == 0 || data.addr() == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}

	if (workloadId >= CELL_SPURS_MAX_WORKLOAD2 || (workloadId >= CELL_SPURS_MAX_WORKLOAD && (spurs->m.flags1 & SF1_32_WORKLOADS) == 0))
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}

	if ((spurs->m.wklEnabled.read_relaxed() & (0x80000000u >> workloadId)) == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_SRCH;
	}

	if (spurs->m.exception)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}

	if (workloadId >= CELL_SPURS_MAX_WORKLOAD)
	{
		*data = spurs->m.wklInfo2[workloadId & 0x0F].arg;
	}
	else
	{
		*data = spurs->m.wklInfo1[workloadId].arg;
	}

	return CELL_OK;
}

s32 cellSpursReadyCountStore(vm::ptr<CellSpurs> spurs, u32 wid, u32 value)
{
	cellSpurs.Warning("%s(spurs_addr=0x%x, wid=%d, value=0x%x)", __FUNCTION__, spurs.addr(), wid, value);

	if (!spurs)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER;
	}
	if (spurs.addr() % 128)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_ALIGN;
	}
	if (wid >= (spurs->m.flags1 & SF1_32_WORKLOADS ? 0x20u : 0x10u) || value > 0xff)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_INVAL;
	}
	if ((spurs->m.wklEnabled.read_relaxed() & (0x80000000u >> wid)) == 0)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_SRCH;
	}
	if (spurs->m.exception.data() || spurs->wklState(wid).read_relaxed() != 2)
	{
		return CELL_SPURS_POLICY_MODULE_ERROR_STAT;
	}

	if (wid < CELL_SPURS_MAX_WORKLOAD)
	{
		spurs->m.wklReadyCount1[wid].exchange((u8)value);
	}
	else
	{
		spurs->m.wklIdleSpuCountOrReadyCount2[wid].exchange((u8)value);
	}
	return CELL_OK;
}

s32 cellSpursReadyCountAdd()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursReadyCountCompareAndSwap()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursReadyCountSwap()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursRequestIdleSpu()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursGetWorkloadInfo()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursWorkloadFlagReceiver2()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursSetExceptionEventHandler()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursUnsetExceptionEventHandler()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursEventFlagInitialize(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, vm::ptr<CellSpursEventFlag> eventFlag, u32 flagClearMode, u32 flagDirection)
{
	cellSpurs.Warning("_cellSpursEventFlagInitialize(spurs_addr=0x%x, taskset_addr=0x%x, eventFlag_addr=0x%x, flagClearMode=%d, flagDirection=%d)",
		spurs.addr(), taskset.addr(), eventFlag.addr(), flagClearMode, flagDirection);

	if (taskset.addr() == 0 && spurs.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align || taskset.addr() % CellSpursTaskset::align || eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (taskset.addr() && taskset->m.wid >= CELL_SPURS_MAX_WORKLOAD2)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	if (flagDirection > CELL_SPURS_EVENT_FLAG_LAST || flagClearMode > CELL_SPURS_EVENT_FLAG_CLEAR_LAST)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	memset(eventFlag.get_ptr(), 0, CellSpursEventFlag::size);
	eventFlag->m.direction = flagDirection;
	eventFlag->m.clearMode = flagClearMode;
	eventFlag->m.spuPort   = CELL_SPURS_EVENT_FLAG_INVALID_SPU_PORT;

	if (taskset.addr())
	{
		eventFlag->m.addr = taskset.addr();
	}
	else
	{
		eventFlag->m.isIwl = 1;
		eventFlag->m.addr  = spurs.addr();
	}

	return CELL_OK;
}

s32 cellSpursEventFlagAttachLv2EventQueue(vm::ptr<CellSpursEventFlag> eventFlag)
{
	cellSpurs.Warning("cellSpursEventFlagAttachLv2EventQueue(eventFlag_addr=0x%x)", eventFlag.addr());

	if (!eventFlag)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_AGAIN;
	}

	if (eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_SPU2PPU && eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_ANY2ANY)
	{
		return CELL_SPURS_TASK_ERROR_PERM;
	}

	if (eventFlag->m.spuPort != CELL_SPURS_EVENT_FLAG_INVALID_SPU_PORT)
	{
		return CELL_SPURS_TASK_ERROR_STAT;
	}

	vm::ptr<CellSpurs> spurs;
	if (eventFlag->m.isIwl == 1)
	{
		spurs.set((u32)eventFlag->m.addr);
	}
	else
	{
		auto taskset = vm::ptr<CellSpursTaskset>::make((u32)eventFlag->m.addr);
		spurs.set((u32)taskset->m.spurs.addr());
	}

	vm::var<u32>      eventQueueId;
	vm::var<u8>       port;
	vm::var<char [8]> evqName;
	memcpy(evqName, "_spuEvF", 8);
	auto rc = spursCreateLv2EventQueue(spurs, eventQueueId, port, 1, vm::ptr<const char>::make(evqName.addr()));
	if (rc != CELL_OK)
	{
		// Return rc if its an error code from SPURS otherwise convert the error code to a SPURS task error code
		return (rc & 0x0FFF0000) == 0x00410000 ? rc : (0x80410900 | (rc & 0xFF));
	}

	if (eventFlag->m.direction == CELL_SPURS_EVENT_FLAG_ANY2ANY)
	{
		vm::var<be_t<u32>> eventPortId;
		rc = sys_event_port_create(vm::ptr<u32>::make(eventPortId.addr()), SYS_EVENT_PORT_LOCAL, 0);
		if (rc == CELL_OK)
		{
			rc = sys_event_port_connect_local(eventPortId.value(), eventQueueId);
			if (rc == CELL_OK)
			{
				eventFlag->m.eventPortId = eventPortId;
				goto success;
			}

			sys_event_port_destroy(eventPortId.value());
		}

		if (spursDetachLv2EventQueue(spurs, port, true/*spursCreated*/) == CELL_OK)
		{
			sys_event_queue_destroy(eventQueueId, SYS_EVENT_QUEUE_DESTROY_FORCE);
		}

		// Return rc if its an error code from SPURS otherwise convert the error code to a SPURS task error code
		return (rc & 0x0FFF0000) == 0x00410000 ? rc : (0x80410900 | (rc & 0xFF));
	}

success:
	eventFlag->m.eventQueueId = eventQueueId;
	eventFlag->m.spuPort      = port;
	return CELL_OK;
}

s32 cellSpursEventFlagDetachLv2EventQueue(vm::ptr<CellSpursEventFlag> eventFlag)
{
	cellSpurs.Warning("cellSpursEventFlagDetachLv2EventQueue(eventFlag_addr=0x%x)", eventFlag.addr());

	if (!eventFlag)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_AGAIN;
	}

	if (eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_SPU2PPU && eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_ANY2ANY)
	{
		return CELL_SPURS_TASK_ERROR_PERM;
	}

	if (eventFlag->m.spuPort == CELL_SPURS_EVENT_FLAG_INVALID_SPU_PORT)
	{
		return CELL_SPURS_TASK_ERROR_STAT;
	}

	if (eventFlag->m.ppuWaitMask || eventFlag->m.ppuPendingRecv)
	{
		return CELL_SPURS_TASK_ERROR_BUSY;
	}

	auto port            = eventFlag->m.spuPort;
	eventFlag->m.spuPort = CELL_SPURS_EVENT_FLAG_INVALID_SPU_PORT;

	vm::ptr<CellSpurs> spurs;
	if (eventFlag->m.isIwl == 1)
	{
		spurs.set((u32)eventFlag->m.addr);
	}
	else
	{
		auto taskset = vm::ptr<CellSpursTaskset>::make((u32)eventFlag->m.addr);
		spurs.set((u32)taskset->m.spurs.addr());
	}

	if(eventFlag->m.direction == CELL_SPURS_EVENT_FLAG_ANY2ANY)
	{
		sys_event_port_disconnect(eventFlag->m.eventPortId);
		sys_event_port_destroy(eventFlag->m.eventPortId);
	}

	auto rc = spursDetachLv2EventQueue(spurs, port, true/*spursCreated*/);
	if (rc == CELL_OK)
	{
		rc = sys_event_queue_destroy(eventFlag->m.eventQueueId, SYS_EVENT_QUEUE_DESTROY_FORCE);
	}

	if (rc != CELL_OK)
	{
		// Return rc if its an error code from SPURS otherwise convert the error code to a SPURS task error code
		return (rc & 0x0FFF0000) == 0x00410000 ? rc : (0x80410900 | (rc & 0xFF));
	}

	return CELL_OK;
}

s32 _cellSpursEventFlagWait(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u16> mask, u32 mode, u32 block)
{
	if (eventFlag.addr() == 0 || mask.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (mode > CELL_SPURS_EVENT_FLAG_WAIT_MODE_LAST)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	if (eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_SPU2PPU && eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_ANY2ANY)
	{
		return CELL_SPURS_TASK_ERROR_PERM;
	}

	if (block && eventFlag->m.spuPort == CELL_SPURS_EVENT_FLAG_INVALID_SPU_PORT)
	{
		return CELL_SPURS_TASK_ERROR_STAT;
	}

	if (eventFlag->m.ppuWaitMask || eventFlag->m.ppuPendingRecv)
	{
		return CELL_SPURS_TASK_ERROR_BUSY;
	}

	u16 relevantEvents = eventFlag->m.events & *mask;
	if (eventFlag->m.direction == CELL_SPURS_EVENT_FLAG_ANY2ANY)
	{
		// Make sure the wait mask and mode specified does not conflict with that of the already waiting tasks.
		// Conflict scenarios:
		// OR  vs OR  - A conflict never occurs
		// OR  vs AND - A conflict occurs if the masks for the two tasks overlap
		// AND vs AND - A conflict occurs if the masks for the two tasks are not the same

		// Determine the set of all already waiting tasks whose wait mode/mask can possibly conflict with the specified wait mode/mask.
		// This set is equal to 'set of all tasks waiting' - 'set of all tasks whose wait conditions have been met'.
		// If the wait mode is OR, we prune the set of all tasks that are waiting in OR mode from the set since a conflict cannot occur
		// with an already waiting task in OR mode.
		u16 relevantWaitSlots = eventFlag->m.spuTaskUsedWaitSlots & ~eventFlag->m.spuTaskPendingRecv;
		if (mode == CELL_SPURS_EVENT_FLAG_OR)
		{
			relevantWaitSlots &= eventFlag->m.spuTaskWaitMode;
		}

		int i = CELL_SPURS_EVENT_FLAG_MAX_WAIT_SLOTS - 1;
		while (relevantWaitSlots)
		{
			if (relevantWaitSlots & 0x0001)
			{
				if (eventFlag->m.spuTaskWaitMask[i] & *mask && eventFlag->m.spuTaskWaitMask[i] != *mask)
				{
					return CELL_SPURS_TASK_ERROR_AGAIN;
				}
			}

			relevantWaitSlots >>= 1;
			i--;
		}
	}

	// There is no need to block if all bits required by the wait operation have already been set or
	// if the wait mode is OR and atleast one of the bits required by the wait operation has been set.
	bool recv;
	if ((*mask & ~relevantEvents) == 0 || (mode == CELL_SPURS_EVENT_FLAG_OR && relevantEvents))
	{
		// If the clear flag is AUTO then clear the bits comnsumed by this thread
		if (eventFlag->m.clearMode == CELL_SPURS_EVENT_FLAG_CLEAR_AUTO)
		{
			eventFlag->m.events &= ~relevantEvents;
		}

		recv = false;
	}
	else
	{
		// If we reach here it means that the conditions for this thread have not been met.
		// If this is a try wait operation then do not block but return an error code.
		if (block == 0)
		{
			return CELL_SPURS_TASK_ERROR_BUSY;
		}

		eventFlag->m.ppuWaitSlotAndMode = 0;
		if (eventFlag->m.direction == CELL_SPURS_EVENT_FLAG_ANY2ANY)
		{
			// Find an unsed wait slot
			int i                    = 0;
			u16 spuTaskUsedWaitSlots = eventFlag->m.spuTaskUsedWaitSlots;
			while (spuTaskUsedWaitSlots & 0x0001)
			{
				spuTaskUsedWaitSlots >>= 1;
				i++;
			}

			if (i == CELL_SPURS_EVENT_FLAG_MAX_WAIT_SLOTS)
			{
				// Event flag has no empty wait slots
				return CELL_SPURS_TASK_ERROR_BUSY;
			}

			// Mark the found wait slot as used by this thread
			eventFlag->m.ppuWaitSlotAndMode = (CELL_SPURS_EVENT_FLAG_MAX_WAIT_SLOTS - 1 - i) << 4;
		}

		// Save the wait mask and mode for this thread
		eventFlag->m.ppuWaitSlotAndMode |= mode;
		eventFlag->m.ppuWaitMask         = *mask;
		recv                             = true;
	}

	u16 receivedEventFlag;
	if (recv) {
		// Block till something happens
		vm::var<sys_event_data> data;
		auto rc = sys_event_queue_receive(eventFlag->m.eventQueueId, data, 0);
		if (rc != CELL_OK)
		{
			assert(0);
		}

		int i = 0;
		if (eventFlag->m.direction == CELL_SPURS_EVENT_FLAG_ANY2ANY)
		{
			i = eventFlag->m.ppuWaitSlotAndMode >> 4;
		}

		receivedEventFlag           = eventFlag->m.pendingRecvTaskEvents[i];
		eventFlag->m.ppuPendingRecv = 0;
	}

	*mask = receivedEventFlag;
	return CELL_OK;
}

s32 cellSpursEventFlagWait(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u16> mask, u32 mode)
{
	cellSpurs.Warning("cellSpursEventFlagWait(eventFlag_addr=0x%x, mask_addr=0x%x, mode=%d)", eventFlag.addr(), mask.addr(), mode);

	return _cellSpursEventFlagWait(eventFlag, mask, mode, 1/*block*/);
}

s32 cellSpursEventFlagClear(vm::ptr<CellSpursEventFlag> eventFlag, u16 bits)
{
	cellSpurs.Warning("cellSpursEventFlagClear(eventFlag_addr=0x%x, bits=0x%x)", eventFlag.addr(), bits);

	if (eventFlag.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	eventFlag->m.events &= ~bits;
	return CELL_OK;
}

s32 cellSpursEventFlagSet(vm::ptr<CellSpursEventFlag> eventFlag, u16 bits)
{
	cellSpurs.Warning("cellSpursEventFlagSet(eventFlag_addr=0x%x, bits=0x%x)", eventFlag.addr(), bits);

	if (eventFlag.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_PPU2SPU && eventFlag->m.direction != CELL_SPURS_EVENT_FLAG_ANY2ANY)
	{
		return CELL_SPURS_TASK_ERROR_PERM;
	}

	u16 ppuEventFlag  = 0;
	bool send         = false;
	int ppuWaitSlot   = 0;
	u16 eventsToClear = 0;
	if (eventFlag->m.direction == CELL_SPURS_EVENT_FLAG_ANY2ANY && eventFlag->m.ppuWaitMask)
	{
		u16 ppuRelevantEvents = (eventFlag->m.events | bits) & eventFlag->m.ppuWaitMask;

		// Unblock the waiting PPU thread if either all the bits being waited by the thread have been set or
		// if the wait mode of the thread is OR and atleast one bit the thread is waiting on has been set
		if ((eventFlag->m.ppuWaitMask & ~ppuRelevantEvents) == 0 ||
			((eventFlag->m.ppuWaitSlotAndMode & 0x0F) == CELL_SPURS_EVENT_FLAG_OR && ppuRelevantEvents != 0))
		{
			eventFlag->m.ppuPendingRecv = 1;
			eventFlag->m.ppuWaitMask    = 0;
			ppuEventFlag                = ppuRelevantEvents;
			eventsToClear               = ppuRelevantEvents;
			ppuWaitSlot                 = eventFlag->m.ppuWaitSlotAndMode >> 4;
			send                        = true;
		}
	}

	int i                  = CELL_SPURS_EVENT_FLAG_MAX_WAIT_SLOTS - 1;
	int j                  = 0;
	u16 relevantWaitSlots  = eventFlag->m.spuTaskUsedWaitSlots & ~eventFlag->m.spuTaskPendingRecv;
	u16 spuTaskPendingRecv = 0;
	u16 pendingRecvTaskEvents[16];
	while (relevantWaitSlots)
	{
		if (relevantWaitSlots & 0x0001)
		{
			u16 spuTaskRelevantEvents = (eventFlag->m.events | bits) & eventFlag->m.spuTaskWaitMask[i];

			// Unblock the waiting SPU task if either all the bits being waited by the task have been set or
			// if the wait mode of the task is OR and atleast one bit the thread is waiting on has been set
			if ((eventFlag->m.spuTaskWaitMask[i] & ~spuTaskRelevantEvents) == 0 || 
				(((eventFlag->m.spuTaskWaitMode >> j) & 0x0001) == CELL_SPURS_EVENT_FLAG_OR && spuTaskRelevantEvents != 0))
			{
				eventsToClear            |= spuTaskRelevantEvents;
				spuTaskPendingRecv       |= 1 << j;
				pendingRecvTaskEvents[j]  = spuTaskRelevantEvents;
			}
		}

		relevantWaitSlots >>= 1;
		i--;
		j++;
	}

	eventFlag->m.events             |= bits;
	eventFlag->m.spuTaskPendingRecv |= spuTaskPendingRecv;

	// If the clear flag is AUTO then clear the bits comnsumed by all tasks marked to be unblocked
	if (eventFlag->m.clearMode == CELL_SPURS_EVENT_FLAG_CLEAR_AUTO)
	{
		 eventFlag->m.events &= ~eventsToClear;
	}

	if (send)
	{
		// Signal the PPU thread to be woken up
		eventFlag->m.pendingRecvTaskEvents[ppuWaitSlot] = ppuEventFlag;
		if (sys_event_port_send(eventFlag->m.eventPortId, 0, 0, 0) != CELL_OK)
		{
			assert(0);
		}
	}

	if (spuTaskPendingRecv)
	{
		// Signal each SPU task whose conditions have been met to be woken up
		for (int i = 0; i < CELL_SPURS_EVENT_FLAG_MAX_WAIT_SLOTS; i++)
		{
			if (spuTaskPendingRecv & (0x8000 >> i))
			{
				eventFlag->m.pendingRecvTaskEvents[i] = pendingRecvTaskEvents[i];
				vm::var<u32> taskset;
				if (eventFlag->m.isIwl)
				{
					cellSpursLookUpTasksetAddress(vm::ptr<CellSpurs>::make((u32)eventFlag->m.addr),
												  vm::ptr<CellSpursTaskset>::make(taskset.addr()),
												  eventFlag->m.waitingTaskWklId[i]);
				}
				else
				{
					taskset.value() = (u32)eventFlag->m.addr;
				}

				auto rc = _cellSpursSendSignal(vm::ptr<CellSpursTaskset>::make(taskset.addr()), eventFlag->m.waitingTaskId[i]);
				if (rc == CELL_SPURS_TASK_ERROR_INVAL || rc == CELL_SPURS_TASK_ERROR_STAT)
				{
					return CELL_SPURS_TASK_ERROR_FATAL;
				}

				if (rc != CELL_OK)
				{
					assert(0);
				}
			}
		}
	}

	return CELL_OK;
}

s32 cellSpursEventFlagTryWait(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u16> mask, u32 mode)
{
	cellSpurs.Warning("cellSpursEventFlagTryWait(eventFlag_addr=0x%x, mask_addr=0x%x, mode=0x%x)", eventFlag.addr(), mask.addr(), mode);

	return _cellSpursEventFlagWait(eventFlag, mask, mode, 0/*block*/);
}

s32 cellSpursEventFlagGetDirection(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u32> direction)
{
	cellSpurs.Warning("cellSpursEventFlagGetDirection(eventFlag_addr=0x%x, direction_addr=0x%x)", eventFlag.addr(), direction.addr());

	if (eventFlag.addr() == 0 || direction.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	*direction = eventFlag->m.direction;
	return CELL_OK;
}

s32 cellSpursEventFlagGetClearMode(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<u32> clear_mode)
{
	cellSpurs.Warning("cellSpursEventFlagGetClearMode(eventFlag_addr=0x%x, clear_mode_addr=0x%x)", eventFlag.addr(), clear_mode.addr());

	if (eventFlag.addr() == 0 || clear_mode.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	*clear_mode = eventFlag->m.clearMode;
	return CELL_OK;
}

s32 cellSpursEventFlagGetTasksetAddress(vm::ptr<CellSpursEventFlag> eventFlag, vm::ptr<CellSpursTaskset> taskset)
{
	cellSpurs.Warning("cellSpursEventFlagGetTasksetAddress(eventFlag_addr=0x%x, taskset_addr=0x%x)", eventFlag.addr(), taskset.addr());

	if (eventFlag.addr() == 0 || taskset.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (eventFlag.addr() % CellSpursEventFlag::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	taskset.set(eventFlag->m.isIwl ? 0 : eventFlag->m.addr);
	return CELL_OK;
}

s32 _cellSpursLFQueueInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursLFQueuePushBody()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursLFQueueDetachLv2EventQueue()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursLFQueueAttachLv2EventQueue()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursLFQueuePopBody()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursLFQueueGetTasksetAddress()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursQueueInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueuePopBody()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueuePushBody()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueAttachLv2EventQueue()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueDetachLv2EventQueue()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueGetTasksetAddress()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueClear()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueDepth()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueGetEntrySize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueSize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursQueueGetDirection()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 spursCreateTaskset(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, u64 args, vm::ptr<const u8[8]> priority,
	u32 max_contention, vm::ptr<const char> name, u32 size, s32 enable_clear_ls)
{
	if (!spurs || !taskset)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (spurs.addr() % CellSpurs::align || taskset.addr() % CellSpursTaskset::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	memset(taskset.get_ptr(), 0, size);

	taskset->m.spurs = spurs;
	taskset->m.args = args;
	taskset->m.enable_clear_ls = enable_clear_ls > 0 ? 1 : 0;
	taskset->m.size = size;

	vm::var<CellSpursWorkloadAttribute> wkl_attr;
	_cellSpursWorkloadAttributeInitialize(wkl_attr, 1 /*revision*/, 0x33 /*sdk_version*/, vm::ptr<const void>::make(SPURS_IMG_ADDR_TASKSET_PM), 0x1E40 /*pm_size*/,
		taskset.addr(), priority, 8 /*min_contention*/, max_contention);
	// TODO: Check return code

	cellSpursWorkloadAttributeSetName(wkl_attr, vm::ptr<const char>::make(0), name);
	// TODO: Check return code

	// TODO: cellSpursWorkloadAttributeSetShutdownCompletionEventHook(wkl_attr, hook, taskset);
	// TODO: Check return code

	vm::var<be_t<u32>> wid;
	cellSpursAddWorkloadWithAttribute(spurs, vm::ptr<u32>::make(wid.addr()), vm::ptr<const CellSpursWorkloadAttribute>::make(wkl_attr.addr()));
	// TODO: Check return code

	taskset->m.wkl_flag_wait_task = 0x80;
	taskset->m.wid                = wid.value();
	// TODO: cellSpursSetExceptionEventHandler(spurs, wid, hook, taskset);
	// TODO: Check return code

	return CELL_OK;
}

s32 cellSpursCreateTasksetWithAttribute(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, vm::ptr<CellSpursTasksetAttribute> attr)
{
	cellSpurs.Warning("%s(spurs=0x%x, taskset=0x%x, attr=0x%x)", __FUNCTION__, spurs.addr(), taskset.addr(), attr.addr());

	if (!attr)
	{
		CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursTasksetAttribute::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (attr->m.revision != CELL_SPURS_TASKSET_ATTRIBUTE_REVISION)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	auto rc = spursCreateTaskset(spurs, taskset, attr->m.args, vm::ptr<const u8[8]>::make(attr.addr() + offsetof(CellSpursTasksetAttribute, m.priority)),
		attr->m.max_contention, vm::ptr<const char>::make(attr->m.name.addr()), attr->m.taskset_size, attr->m.enable_clear_ls);

	if (attr->m.taskset_size >= CellSpursTaskset2::size)
	{
		// TODO: Implement this
	}

	return rc;
}

s32 cellSpursCreateTaskset(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, u64 args, vm::ptr<const u8[8]> priority, u32 maxContention)
{
	cellSpurs.Warning("cellSpursCreateTaskset(spurs_addr=0x%x, taskset_addr=0x%x, args=0x%llx, priority_addr=0x%x, maxContention=%d)",
		spurs.addr(), taskset.addr(), args, priority.addr(), maxContention);

	return spursCreateTaskset(spurs, taskset, args, priority, maxContention, vm::ptr<const char>::make(0), CellSpursTaskset::size, 0);
}

s32 cellSpursJoinTaskset(vm::ptr<CellSpursTaskset> taskset)
{
	cellSpurs.Warning("cellSpursJoinTaskset(taskset_addr=0x%x)", taskset.addr());

	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursGetTasksetId(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u32> wid)
{
	cellSpurs.Warning("cellSpursGetTasksetId(taskset_addr=0x%x, wid=0x%x)", taskset.addr(), wid.addr());

	if (!taskset || !wid)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (taskset.addr() % CellSpursTaskset::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (taskset->m.wid >= CELL_SPURS_MAX_WORKLOAD)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	*wid = taskset->m.wid;
	return CELL_OK;
}

s32 cellSpursShutdownTaskset(vm::ptr<CellSpursTaskset> taskset)
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 spursCreateTask(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u32> task_id, vm::ptr<u32> elf_addr, vm::ptr<u32> context_addr, u32 context_size, vm::ptr<CellSpursTaskLsPattern> ls_pattern, vm::ptr<CellSpursTaskArgument> arg)
{
	if (!taskset || !elf_addr)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (elf_addr.addr() % 16)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	auto sdk_version = spursGetSdkVersion();
	if (sdk_version < 0x27FFFF)
	{
		if (context_addr.addr() % 16)
		{
			return CELL_SPURS_TASK_ERROR_ALIGN;
		}
	}
	else
	{
		if (context_addr.addr() % 128)
		{
			return CELL_SPURS_TASK_ERROR_ALIGN;
		}
	}

	u32 alloc_ls_blocks = 0;
	if (context_addr.addr() != 0)
	{
		if (context_size < CELL_SPURS_TASK_EXECUTION_CONTEXT_SIZE)
		{
			return CELL_SPURS_TASK_ERROR_INVAL;
		}

		alloc_ls_blocks = context_size > 0x3D400 ? 0x7A : ((context_size - 0x400) >> 11);
		if (ls_pattern.addr() != 0)
		{
			u128 ls_pattern_128 = u128::from64r(ls_pattern->_u64[0], ls_pattern->_u64[1]);
			u32 ls_blocks       = 0;
			for (auto i = 0; i < 128; i++)
			{
				if (ls_pattern_128._bit[i])
				{
					ls_blocks++;
				}
			}

			if (ls_blocks > alloc_ls_blocks)
			{
				return CELL_SPURS_TASK_ERROR_INVAL;
			}

			u128 _0 = u128::from32(0);
			if ((ls_pattern_128 & u128::from32r(0xFC000000)) != _0)
			{
				// Prevent save/restore to SPURS management area
				return CELL_SPURS_TASK_ERROR_INVAL;
			}
		}
	}
	else
	{
		alloc_ls_blocks = 0;
	}

	// TODO: Verify the ELF header is proper and all its load segments are at address >= 0x3000

	u32 tmp_task_id;
	for (tmp_task_id = 0; tmp_task_id < CELL_SPURS_MAX_TASK; tmp_task_id++)
	{
		if (!taskset->m.enabled.value()._bit[tmp_task_id])
		{
			auto enabled              = taskset->m.enabled.value();
			enabled._bit[tmp_task_id] = true;
			taskset->m.enabled        = enabled;
			break;
		}
	}

	if (tmp_task_id >= CELL_SPURS_MAX_TASK)
	{
		CELL_SPURS_TASK_ERROR_AGAIN;
	}

	taskset->m.task_info[tmp_task_id].elf_addr.set(elf_addr.addr());
	taskset->m.task_info[tmp_task_id].context_save_storage_and_alloc_ls_blocks = (context_addr.addr() | alloc_ls_blocks);
	taskset->m.task_info[tmp_task_id].args                                     = *arg;
	if (ls_pattern.addr())
	{
		taskset->m.task_info[tmp_task_id].ls_pattern = *ls_pattern;
	}

	*task_id = tmp_task_id;
	return CELL_OK;
}

s32 spursTaskStart(vm::ptr<CellSpursTaskset> taskset, u32 taskId)
{
	auto pendingReady         = taskset->m.pending_ready.value();
	pendingReady._bit[taskId] = true;
	taskset->m.pending_ready  = pendingReady;

	cellSpursSendWorkloadSignal(vm::ptr<CellSpurs>::make((u32)taskset->m.spurs.addr()), taskset->m.wid);
	auto rc = cellSpursWakeUp(GetCurrentPPUThread(), vm::ptr<CellSpurs>::make((u32)taskset->m.spurs.addr()));
	if (rc != CELL_OK)
	{
		if (rc == CELL_SPURS_POLICY_MODULE_ERROR_STAT)
		{
			rc = CELL_SPURS_TASK_ERROR_STAT;
		}
		else
		{
			assert(0);
		}
	}

	return rc;
}

s32 cellSpursCreateTask(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u32> taskId, u32 elf_addr, u32 context_addr, u32 context_size, vm::ptr<CellSpursTaskLsPattern> lsPattern,
	vm::ptr<CellSpursTaskArgument> argument)
{
	cellSpurs.Warning("cellSpursCreateTask(taskset_addr=0x%x, taskID_addr=0x%x, elf_addr_addr=0x%x, context_addr_addr=0x%x, context_size=%d, lsPattern_addr=0x%x, argument_addr=0x%x)",
		taskset.addr(), taskId.addr(), elf_addr, context_addr, context_size, lsPattern.addr(), argument.addr());

	if (!taskset)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (taskset.addr() % CellSpursTaskset::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	vm::var<u32> tmpTaskId;
	auto rc = spursCreateTask(taskset, tmpTaskId, vm::ptr<u32>::make(elf_addr), vm::ptr<u32>::make(context_addr), context_size, lsPattern, argument);
	if (rc != CELL_OK) 
	{
		return rc;
	}

	rc = spursTaskStart(taskset, tmpTaskId);
	if (rc != CELL_OK) 
	{
		return rc;
	}

	*taskId = tmpTaskId;
	return CELL_OK;
}

s32 _cellSpursSendSignal(vm::ptr<CellSpursTaskset> taskset, u32 taskId)
{
	if (!taskset)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (taskset.addr() % CellSpursTaskset::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (taskId >= CELL_SPURS_MAX_TASK || taskset->m.wid >= CELL_SPURS_MAX_WORKLOAD2)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	auto _0       = be_t<u128>::make(u128::from32(0));
	auto disabled = taskset->m.enabled.value()._bit[taskId] ? false : true;
	auto invalid  = (taskset->m.ready & taskset->m.pending_ready) != _0 || (taskset->m.running & taskset->m.waiting) != _0 || disabled ||
					((taskset->m.running | taskset->m.ready | taskset->m.pending_ready | taskset->m.waiting | taskset->m.signalled) & be_t<u128>::make(~taskset->m.enabled.value())) != _0;

	if (invalid)
	{
		return CELL_SPURS_TASK_ERROR_SRCH;
	}

	auto shouldSignal      = (taskset->m.waiting & be_t<u128>::make(~taskset->m.signalled.value()) & be_t<u128>::make(u128::fromBit(taskId))) != _0 ? true : false;
	auto signalled         = taskset->m.signalled.value();
	signalled._bit[taskId] = true;
	taskset->m.signalled   = signalled;
	if (shouldSignal)
	{
		cellSpursSendWorkloadSignal(vm::ptr<CellSpurs>::make((u32)taskset->m.spurs.addr()), taskset->m.wid);
		auto rc = cellSpursWakeUp(GetCurrentPPUThread(), vm::ptr<CellSpurs>::make((u32)taskset->m.spurs.addr()));
		if (rc == CELL_SPURS_POLICY_MODULE_ERROR_STAT)
		{
			return CELL_SPURS_TASK_ERROR_STAT;
		}

		if (rc != CELL_OK)
		{
			assert(0);
		}
	}

	return CELL_OK;
}

s32 cellSpursCreateTaskWithAttribute()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTasksetAttributeSetName(vm::ptr<CellSpursTasksetAttribute> attr, vm::ptr<const char> name)
{
	cellSpurs.Warning("%s(attr=0x%x, name=0x%x)", __FUNCTION__, attr.addr(), name.addr());

	if (!attr || !name)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursTasksetAttribute::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	attr->m.name = name;
	return CELL_OK;
}

s32 cellSpursTasksetAttributeSetTasksetSize(vm::ptr<CellSpursTasksetAttribute> attr, u32 size)
{
	cellSpurs.Warning("%s(attr=0x%x, size=0x%x)", __FUNCTION__, attr.addr(), size);

	if (!attr)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursTasksetAttribute::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (size != CellSpursTaskset::size && size != CellSpursTaskset2::size)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	attr->m.taskset_size = size;
	return CELL_OK;
}

s32 cellSpursTasksetAttributeEnableClearLS(vm::ptr<CellSpursTasksetAttribute> attr, s32 enable)
{
	cellSpurs.Warning("%s(attr=0x%x, enable=%d)", __FUNCTION__, attr.addr(), enable);

	if (!attr)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (attr.addr() % CellSpursTasksetAttribute::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	attr->m.enable_clear_ls = enable ? 1 : 0;
	return CELL_OK;
}

s32 _cellSpursTasksetAttribute2Initialize(vm::ptr<CellSpursTasksetAttribute2> attribute, u32 revision)
{
	cellSpurs.Warning("_cellSpursTasksetAttribute2Initialize(attribute_addr=0x%x, revision=%d)", attribute.addr(), revision);

	memset(attribute.get_ptr(), 0, CellSpursTasksetAttribute2::size);
	attribute->m.revision = revision;
	attribute->m.name.set(0);
	attribute->m.args = 0;

	for (s32 i = 0; i < 8; i++)
	{
		attribute->m.priority[i] = 1;
	}

	attribute->m.max_contention = 8;
	attribute->m.enable_clear_ls = 0;
	attribute->m.task_name_buffer.set(0);
	return CELL_OK;
}

s32 cellSpursTaskExitCodeGet()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTaskExitCodeInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTaskExitCodeTryGet()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTaskGetLoadableSegmentPattern()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTaskGetReadOnlyAreaPattern()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTaskGenerateLsPattern()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursTaskAttributeInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTaskAttributeSetExitCodeContainer()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursTaskAttribute2Initialize(vm::ptr<CellSpursTaskAttribute2> attribute, u32 revision)
{
	cellSpurs.Warning("_cellSpursTaskAttribute2Initialize(attribute_addr=0x%x, revision=%d)", attribute.addr(), revision);

	attribute->revision = revision;
	attribute->sizeContext = 0;
	attribute->eaContext = 0;

	for (s32 c = 0; c < 4; c++)
	{
		attribute->lsPattern._u32[c] = 0;
	}

	attribute->name_addr = 0;

	return CELL_OK;
}

s32 cellSpursTaskGetContextSaveAreaSize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursCreateTaskset2(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset2> taskset, vm::ptr<CellSpursTasksetAttribute2> attr)
{
	cellSpurs.Warning("%s(spurs=0x%x, taskset=0x%x, attr=0x%x)", __FUNCTION__, spurs.addr(), taskset.addr(), attr.addr());

	vm::ptr<CellSpursTasksetAttribute2> tmp_attr;

	if (!attr)
	{
		attr.set(tmp_attr.addr());
		_cellSpursTasksetAttribute2Initialize(attr, 0);
	}

	auto rc = spursCreateTaskset(spurs, vm::ptr<CellSpursTaskset>::make(taskset.addr()), attr->m.args,
		vm::ptr<const u8[8]>::make(attr.addr() + offsetof(CellSpursTasksetAttribute, m.priority)),
		attr->m.max_contention, vm::ptr<const char>::make(attr->m.name.addr()), CellSpursTaskset2::size, (u8)attr->m.enable_clear_ls);
	if (rc != CELL_OK)
	{
		return rc;
	}

	if (attr->m.task_name_buffer.addr() % CellSpursTaskNameBuffer::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	// TODO: Implement rest of the function
	return CELL_OK;
}

s32 cellSpursCreateTask2()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJoinTask2()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTryJoinTask2()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursDestroyTaskset2()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursCreateTask2WithBinInfo()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursTasksetSetExceptionEventHandler(vm::ptr<CellSpursTaskset> taskset, vm::ptr<u64> handler, vm::ptr<u64> arg)
{
	cellSpurs.Warning("%s(taskset=0x5x, handler=0x%x, arg=0x%x)", __FUNCTION__, taskset.addr(), handler.addr(), arg.addr());

	if (!taskset || !handler)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (taskset.addr() % CellSpursTaskset::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (taskset->m.wid >= CELL_SPURS_MAX_WORKLOAD)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	if (taskset->m.exception_handler != 0)
	{
		return CELL_SPURS_TASK_ERROR_BUSY;
	}

	taskset->m.exception_handler = handler;
	taskset->m.exception_handler_arg = arg;
	return CELL_OK;
}

s32 cellSpursTasksetUnsetExceptionEventHandler(vm::ptr<CellSpursTaskset> taskset)
{
	cellSpurs.Warning("%s(taskset=0x%x)", __FUNCTION__, taskset.addr());

	if (!taskset)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (taskset.addr() % CellSpursTaskset::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (taskset->m.wid >= CELL_SPURS_MAX_WORKLOAD)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	taskset->m.exception_handler.set(0);
	taskset->m.exception_handler_arg.set(0);
	return CELL_OK;
}

s32 cellSpursLookUpTasksetAddress(vm::ptr<CellSpurs> spurs, vm::ptr<CellSpursTaskset> taskset, u32 id)
{
	cellSpurs.Warning("%s(spurs=0x%x, taskset=0x%x, id=0x%x)", __FUNCTION__, spurs.addr(), taskset.addr(), id);

	if (taskset.addr() == 0)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	vm::var<be_t<u64>> data;
	auto rc = cellSpursGetWorkloadData(spurs, vm::ptr<u64>::make(data.addr()), id);
	if (rc != CELL_OK)
	{
		// Convert policy module error code to a task error code
		return rc ^ 0x100;
	}

	taskset.set((u32)data.value());
	return CELL_OK;
}

s32 cellSpursTasksetGetSpursAddress(vm::ptr<const CellSpursTaskset> taskset, vm::ptr<u32> spurs)
{
	cellSpurs.Warning("%s(taskset=0x%x, spurs=0x%x)", __FUNCTION__, taskset.addr(), spurs.addr());

	if (!taskset || !spurs)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (taskset.addr() % CellSpursTaskset::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	if (taskset->m.wid >= CELL_SPURS_MAX_WORKLOAD)
	{
		return CELL_SPURS_TASK_ERROR_INVAL;
	}

	*spurs = (u32)taskset->m.spurs.addr();
	return CELL_OK;
}

s32 cellSpursGetTasksetInfo()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursTasksetAttributeInitialize(vm::ptr<CellSpursTasksetAttribute> attribute, u32 revision, u32 sdk_version, u64 args, vm::ptr<const u8> priority, u32 max_contention)
{
	cellSpurs.Warning("%s(attribute=0x%x, revision=%d, skd_version=%d, args=0x%llx, priority=0x%x, max_contention=%d)",
		__FUNCTION__, attribute.addr(), revision, sdk_version, args, priority.addr(), max_contention);

	if (!attribute)
	{
		return CELL_SPURS_TASK_ERROR_NULL_POINTER;
	}

	if (attribute.addr() % CellSpursTasksetAttribute::align)
	{
		return CELL_SPURS_TASK_ERROR_ALIGN;
	}

	for (u32 i = 0; i < 8; i++)
	{
		if (priority[i] > 0xF)
		{
			return CELL_SPURS_TASK_ERROR_INVAL;
		}
	}

	memset(attribute.get_ptr(), 0, CellSpursTasksetAttribute::size);
	attribute->m.revision = revision;
	attribute->m.sdk_version = sdk_version;
	attribute->m.args = args;
	memcpy(attribute->m.priority, priority.get_ptr(), 8);
	attribute->m.taskset_size = CellSpursTaskset::size;
	attribute->m.max_contention = max_contention;
	return CELL_OK;
}

s32 cellSpursCreateJobChainWithAttribute()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursCreateJobChain()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJoinJobChain()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursKickJobChain()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursJobChainAttributeInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursGetJobChainId()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobChainSetExceptionEventHandler()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobChainUnsetExceptionEventHandler()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursGetJobChainInfo()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobChainGetSpursAddress()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobGuardInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobChainAttributeSetName()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursShutdownJobChain()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobChainAttributeSetHaltOnError()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobChainAttributeSetJobTypeMemoryCheck()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobGuardNotify()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobGuardReset()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursRunJobChain()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobChainGetError()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursGetJobPipelineInfo()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobSetMaxGrab()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursJobHeaderSetJobbin2Param()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursAddUrgentCommand()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursAddUrgentCall()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursBarrierInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursBarrierGetTasksetAddress()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 _cellSpursSemaphoreInitialize()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

s32 cellSpursSemaphoreGetTasksetAddress()
{
	UNIMPLEMENTED_FUNC(cellSpurs);
	return CELL_OK;
}

Module cellSpurs("cellSpurs", []()
{
	// Core 
	REG_FUNC(cellSpurs, cellSpursInitialize);
	REG_FUNC(cellSpurs, cellSpursInitializeWithAttribute);
	REG_FUNC(cellSpurs, cellSpursInitializeWithAttribute2);
	REG_FUNC(cellSpurs, cellSpursFinalize);
	REG_FUNC(cellSpurs, _cellSpursAttributeInitialize);
	REG_FUNC(cellSpurs, cellSpursAttributeSetMemoryContainerForSpuThread);
	REG_FUNC(cellSpurs, cellSpursAttributeSetNamePrefix);
	REG_FUNC(cellSpurs, cellSpursAttributeEnableSpuPrintfIfAvailable);
	REG_FUNC(cellSpurs, cellSpursAttributeSetSpuThreadGroupType);
	REG_FUNC(cellSpurs, cellSpursAttributeEnableSystemWorkload);
	REG_FUNC(cellSpurs, cellSpursGetSpuThreadGroupId);
	REG_FUNC(cellSpurs, cellSpursGetNumSpuThread);
	REG_FUNC(cellSpurs, cellSpursGetSpuThreadId);
	REG_FUNC(cellSpurs, cellSpursGetInfo);
	REG_FUNC(cellSpurs, cellSpursSetMaxContention);
	REG_FUNC(cellSpurs, cellSpursSetPriorities);
	REG_FUNC(cellSpurs, cellSpursSetPreemptionVictimHints);
	REG_FUNC(cellSpurs, cellSpursAttachLv2EventQueue);
	REG_FUNC(cellSpurs, cellSpursDetachLv2EventQueue);
	REG_FUNC(cellSpurs, cellSpursEnableExceptionEventHandler);
	REG_FUNC(cellSpurs, cellSpursSetGlobalExceptionEventHandler);
	REG_FUNC(cellSpurs, cellSpursUnsetGlobalExceptionEventHandler);
	REG_FUNC(cellSpurs, cellSpursSetExceptionEventHandler);
	REG_FUNC(cellSpurs, cellSpursUnsetExceptionEventHandler);

	// Event flag
	REG_FUNC(cellSpurs, _cellSpursEventFlagInitialize);
	REG_FUNC(cellSpurs, cellSpursEventFlagAttachLv2EventQueue);
	REG_FUNC(cellSpurs, cellSpursEventFlagDetachLv2EventQueue);
	REG_FUNC(cellSpurs, cellSpursEventFlagWait);
	REG_FUNC(cellSpurs, cellSpursEventFlagClear);
	REG_FUNC(cellSpurs, cellSpursEventFlagSet);
	REG_FUNC(cellSpurs, cellSpursEventFlagTryWait);
	REG_FUNC(cellSpurs, cellSpursEventFlagGetDirection);
	REG_FUNC(cellSpurs, cellSpursEventFlagGetClearMode);
	REG_FUNC(cellSpurs, cellSpursEventFlagGetTasksetAddress);

	// Taskset
	REG_FUNC(cellSpurs, cellSpursCreateTaskset);
	REG_FUNC(cellSpurs, cellSpursCreateTasksetWithAttribute);
	REG_FUNC(cellSpurs, _cellSpursTasksetAttributeInitialize);
	REG_FUNC(cellSpurs, _cellSpursTasksetAttribute2Initialize);
	REG_FUNC(cellSpurs, cellSpursTasksetAttributeSetName);
	REG_FUNC(cellSpurs, cellSpursTasksetAttributeSetTasksetSize);
	REG_FUNC(cellSpurs, cellSpursTasksetAttributeEnableClearLS);
	REG_FUNC(cellSpurs, cellSpursJoinTaskset);
	REG_FUNC(cellSpurs, cellSpursGetTasksetId);
	REG_FUNC(cellSpurs, cellSpursShutdownTaskset);
	REG_FUNC(cellSpurs, cellSpursCreateTask);
	REG_FUNC(cellSpurs, cellSpursCreateTaskWithAttribute);
	REG_FUNC(cellSpurs, _cellSpursTaskAttributeInitialize);
	REG_FUNC(cellSpurs, _cellSpursTaskAttribute2Initialize);
	REG_FUNC(cellSpurs, cellSpursTaskAttributeSetExitCodeContainer);
	REG_FUNC(cellSpurs, cellSpursTaskExitCodeGet);
	REG_FUNC(cellSpurs, cellSpursTaskExitCodeInitialize);
	REG_FUNC(cellSpurs, cellSpursTaskExitCodeTryGet);
	REG_FUNC(cellSpurs, cellSpursTaskGetLoadableSegmentPattern);
	REG_FUNC(cellSpurs, cellSpursTaskGetReadOnlyAreaPattern);
	REG_FUNC(cellSpurs, cellSpursTaskGenerateLsPattern);
	REG_FUNC(cellSpurs, cellSpursTaskGetContextSaveAreaSize);
	REG_FUNC(cellSpurs, _cellSpursSendSignal);
	REG_FUNC(cellSpurs, cellSpursCreateTaskset2);
	REG_FUNC(cellSpurs, cellSpursCreateTask2);
	REG_FUNC(cellSpurs, cellSpursJoinTask2);
	REG_FUNC(cellSpurs, cellSpursTryJoinTask2);
	REG_FUNC(cellSpurs, cellSpursDestroyTaskset2);
	REG_FUNC(cellSpurs, cellSpursCreateTask2WithBinInfo);
	REG_FUNC(cellSpurs, cellSpursLookUpTasksetAddress);
	REG_FUNC(cellSpurs, cellSpursTasksetGetSpursAddress);
	REG_FUNC(cellSpurs, cellSpursGetTasksetInfo);
	REG_FUNC(cellSpurs, cellSpursTasksetSetExceptionEventHandler);
	REG_FUNC(cellSpurs, cellSpursTasksetUnsetExceptionEventHandler);

	// Job Chain
	REG_FUNC(cellSpurs, cellSpursCreateJobChain);
	REG_FUNC(cellSpurs, cellSpursCreateJobChainWithAttribute);
	REG_FUNC(cellSpurs, cellSpursShutdownJobChain);
	REG_FUNC(cellSpurs, cellSpursJoinJobChain);
	REG_FUNC(cellSpurs, cellSpursKickJobChain);
	REG_FUNC(cellSpurs, cellSpursRunJobChain);
	REG_FUNC(cellSpurs, cellSpursJobChainGetError);
	REG_FUNC(cellSpurs, _cellSpursJobChainAttributeInitialize);
	REG_FUNC(cellSpurs, cellSpursJobChainAttributeSetName);
	REG_FUNC(cellSpurs, cellSpursJobChainAttributeSetHaltOnError);
	REG_FUNC(cellSpurs, cellSpursJobChainAttributeSetJobTypeMemoryCheck);
	REG_FUNC(cellSpurs, cellSpursGetJobChainId);
	REG_FUNC(cellSpurs, cellSpursJobChainSetExceptionEventHandler);
	REG_FUNC(cellSpurs, cellSpursJobChainUnsetExceptionEventHandler);
	REG_FUNC(cellSpurs, cellSpursGetJobChainInfo);
	REG_FUNC(cellSpurs, cellSpursJobChainGetSpursAddress);

	// Job Guard
	REG_FUNC(cellSpurs, cellSpursJobGuardInitialize);
	REG_FUNC(cellSpurs, cellSpursJobGuardNotify);
	REG_FUNC(cellSpurs, cellSpursJobGuardReset);
	
	// LFQueue
	REG_FUNC(cellSpurs, _cellSpursLFQueueInitialize);
	REG_FUNC(cellSpurs, _cellSpursLFQueuePushBody);
	REG_FUNC(cellSpurs, cellSpursLFQueueAttachLv2EventQueue);
	REG_FUNC(cellSpurs, cellSpursLFQueueDetachLv2EventQueue);
	REG_FUNC(cellSpurs, _cellSpursLFQueuePopBody);
	REG_FUNC(cellSpurs, cellSpursLFQueueGetTasksetAddress);

	// Queue
	REG_FUNC(cellSpurs, _cellSpursQueueInitialize);
	REG_FUNC(cellSpurs, cellSpursQueuePopBody);
	REG_FUNC(cellSpurs, cellSpursQueuePushBody);
	REG_FUNC(cellSpurs, cellSpursQueueAttachLv2EventQueue);
	REG_FUNC(cellSpurs, cellSpursQueueDetachLv2EventQueue);
	REG_FUNC(cellSpurs, cellSpursQueueGetTasksetAddress);
	REG_FUNC(cellSpurs, cellSpursQueueClear);
	REG_FUNC(cellSpurs, cellSpursQueueDepth);
	REG_FUNC(cellSpurs, cellSpursQueueGetEntrySize);
	REG_FUNC(cellSpurs, cellSpursQueueSize);
	REG_FUNC(cellSpurs, cellSpursQueueGetDirection);

	// Workload
	REG_FUNC(cellSpurs, cellSpursWorkloadAttributeSetName);
	REG_FUNC(cellSpurs, cellSpursWorkloadAttributeSetShutdownCompletionEventHook);
	REG_FUNC(cellSpurs, cellSpursAddWorkloadWithAttribute);
	REG_FUNC(cellSpurs, cellSpursAddWorkload);
	REG_FUNC(cellSpurs, cellSpursShutdownWorkload);
	REG_FUNC(cellSpurs, cellSpursWaitForWorkloadShutdown);
	REG_FUNC(cellSpurs, cellSpursRemoveWorkload);
	REG_FUNC(cellSpurs, cellSpursReadyCountStore);
	REG_FUNC(cellSpurs, cellSpursGetWorkloadFlag);
	REG_FUNC(cellSpurs, _cellSpursWorkloadFlagReceiver);
	REG_FUNC(cellSpurs, _cellSpursWorkloadAttributeInitialize);
	REG_FUNC(cellSpurs, cellSpursSendWorkloadSignal);
	REG_FUNC(cellSpurs, cellSpursGetWorkloadData);
	REG_FUNC(cellSpurs, cellSpursReadyCountAdd);
	REG_FUNC(cellSpurs, cellSpursReadyCountCompareAndSwap);
	REG_FUNC(cellSpurs, cellSpursReadyCountSwap);
	REG_FUNC(cellSpurs, cellSpursRequestIdleSpu);
	REG_FUNC(cellSpurs, cellSpursGetWorkloadInfo);
	REG_FUNC(cellSpurs, cellSpursGetSpuGuid);
	REG_FUNC(cellSpurs, _cellSpursWorkloadFlagReceiver2);
	REG_FUNC(cellSpurs, cellSpursGetJobPipelineInfo);
	REG_FUNC(cellSpurs, cellSpursJobSetMaxGrab);
	REG_FUNC(cellSpurs, cellSpursJobHeaderSetJobbin2Param);

	REG_FUNC(cellSpurs, cellSpursWakeUp);
	REG_FUNC(cellSpurs, cellSpursAddUrgentCommand);
	REG_FUNC(cellSpurs, cellSpursAddUrgentCall);

	REG_FUNC(cellSpurs, cellSpursBarrierInitialize);
	REG_FUNC(cellSpurs, cellSpursBarrierGetTasksetAddress);

	REG_FUNC(cellSpurs, _cellSpursSemaphoreInitialize);
	REG_FUNC(cellSpurs, cellSpursSemaphoreGetTasksetAddress);

	// Trace
	REG_FUNC(cellSpurs, cellSpursTraceInitialize);
	REG_FUNC(cellSpurs, cellSpursTraceStart);
	REG_FUNC(cellSpurs, cellSpursTraceStop);
	REG_FUNC(cellSpurs, cellSpursTraceFinalize);
});

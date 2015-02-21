#pragma once

struct sys_semaphore_attribute
{
	be_t<u32> protocol;
	be_t<u32> pshared; // undefined
	be_t<u64> ipc_key; // undefined
	be_t<s32> flags; // undefined
	be_t<u32> pad; // not used
	union
	{
		char name[8];
		u64 name_u64;
	};
};

struct Semaphore
{
	sleep_queue_t queue;
	atomic_le_t<s32> value;

	const s32 max;
	const u32 protocol;
	const u64 name;

	Semaphore(s32 initial_count, s32 max_count, u32 protocol, u64 name)
		: max(max_count)
		, protocol(protocol)
		, name(name)
	{
		value.write_relaxed(initial_count);
	}
};

// Aux
void sys_semaphore_attribute_initialize(vm::ptr<sys_semaphore_attribute> attr);

// SysCalls
s32 sys_semaphore_create(vm::ptr<u32> sem, vm::ptr<sys_semaphore_attribute> attr, s32 initial_count, s32 max_count);
s32 sys_semaphore_destroy(u32 sem_id);
s32 sys_semaphore_wait(u32 sem_id, u64 timeout);
s32 sys_semaphore_trywait(u32 sem_id);
s32 sys_semaphore_post(u32 sem_id, s32 count);
s32 sys_semaphore_get_value(u32 sem_id, vm::ptr<s32> count);

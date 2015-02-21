#pragma once

#define FIX_SPUQ(x) ((u64)x | 0x5350555100000000ULL)
// arbitrary code to prevent "special" zero value in key argument

enum EventQueueType
{
	SYS_PPU_QUEUE = 1,
	SYS_SPU_QUEUE = 2,
};

enum EventQueueIpcKey
{
	SYS_EVENT_QUEUE_LOCAL = 0x00,
};

enum EventQueueDestroyMode
{
	// DEFAULT = 0,
	SYS_EVENT_QUEUE_DESTROY_FORCE = 1,
};

enum EventPortType
{
	SYS_EVENT_PORT_LOCAL = 1,
};

enum EventPortName
{
	SYS_EVENT_PORT_NO_NAME = 0,
};

enum EventSourceType
{
	SYS_SPU_THREAD_EVENT_USER = 1,
	/* SYS_SPU_THREAD_EVENT_DMA = 2, */ // not supported
};

enum EventSourceKey : u64
{
	SYS_SPU_THREAD_EVENT_USER_KEY      = 0xFFFFFFFF53505501ull,
	SYS_SPU_THREAD_EVENT_DMA_KEY       = 0xFFFFFFFF53505502ull,
	SYS_SPU_THREAD_EVENT_EXCEPTION_KEY = 0xFFFFFFFF53505503ull,
};

struct sys_event_queue_attr
{
	be_t<u32> protocol; // SYS_SYNC_PRIORITY or SYS_SYNC_FIFO
	be_t<s32> type; // SYS_PPU_QUEUE or SYS_SPU_QUEUE
	union
	{
		char name[8];
		u64 name_u64;
	};
};

struct sys_event_data
{
	be_t<u64> source;
	be_t<u64> data1;
	be_t<u64> data2;
	be_t<u64> data3;
};

struct EventQueue;

struct EventPort
{
	u64 name; // generated or user-specified code that is passed to sys_event_data struct
	std::shared_ptr<EventQueue> eq; // event queue this port has been connected to
	std::mutex m_mutex; // may be locked until the event sending is finished

	EventPort(u64 name = 0)
		: eq(nullptr)
		, name(name)
	{
	}
};

class EventRingBuffer
{
	std::vector<sys_event_data> data;
	std::mutex m_mutex;
	u32 buf_pos;
	u32 buf_count;

public:
	const u32 size;

	EventRingBuffer(u32 size)
		: size(size)
		, buf_pos(0)
		, buf_count(0)
	{
		data.resize(size);
	}

	void clear()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		buf_count = 0;
		buf_pos = 0;
	}

	bool push(u64 name, u64 d1, u64 d2, u64 d3)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (buf_count >= size) return false;

		sys_event_data& ref = data[(buf_pos + buf_count++) % size];
		ref.source = name;
		ref.data1 = d1;
		ref.data2 = d2;
		ref.data3 = d3;

		return true;
	}

	bool pop(sys_event_data& ref)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (!buf_count) return false;

		sys_event_data& from = data[buf_pos];
		buf_pos = (buf_pos + 1) % size;
		buf_count--;
		ref.source = from.source;
		ref.data1 = from.data1;
		ref.data2 = from.data2;
		ref.data3 = from.data3;

		return true;
	}

	u32 pop_all(sys_event_data* ptr, u32 max)
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		u32 res = 0;
		while (buf_count && max)
		{
			sys_event_data& from = data[buf_pos];
			ptr->source = from.source;
			ptr->data1 = from.data1;
			ptr->data2 = from.data2;
			ptr->data3 = from.data3;
			buf_pos = (buf_pos + 1) % size;
			buf_count--;
			max--;
			ptr++;
			res++;
		}
		return res;
	}

	u32 count() const
	{
		return buf_count;
	}
};

class EventPortList
{
	std::vector<std::shared_ptr<EventPort>> data;
	std::mutex m_mutex;

public:

	void clear()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		for (u32 i = 0; i < data.size(); i++)
		{
			// TODO: force all ports to disconnect
			//std::lock_guard<std::mutex> lock2(data[i]->m_mutex);
			//data[i]->eq = nullptr;
		}
		data.clear();
	}

	void add(std::shared_ptr<EventPort>& port)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		data.push_back(port);
	}

	void remove(std::shared_ptr<EventPort>& port)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		for (u32 i = 0; i < data.size(); i++)
		{
			if (data[i].get() == port.get())
			{
				data.erase(data.begin() + i);
				return;
			}
		}
	}
};

struct EventQueue
{
	sleep_queue_t sq;
	EventPortList ports;
	EventRingBuffer events;
	atomic_le_t<u32> owner;

	const union
	{
		u64 name_u64;
		char name[8];
	};
	const u32 protocol;
	const int type;
	const u64 key;

	EventQueue(u32 protocol, int type, u64 name, u64 key, int size)
		: type(type)
		, protocol(protocol)
		, name_u64(name)
		, key(key)
		, events(size) // size: max event count this queue can hold
	{
		owner.write_relaxed(0);
	}
};

// Aux
u32 event_port_create(u64 name);
void sys_event_queue_attribute_initialize(vm::ptr<sys_event_queue_attr> attr);

// SysCalls
s32 sys_event_queue_create(vm::ptr<u32> equeue_id, vm::ptr<sys_event_queue_attr> attr, u64 event_queue_key, s32 size);
s32 sys_event_queue_destroy(u32 equeue_id, s32 mode);
s32 sys_event_queue_receive(u32 equeue_id, vm::ptr<sys_event_data> dummy_event, u64 timeout);
s32 sys_event_queue_tryreceive(u32 equeue_id, vm::ptr<sys_event_data> event_array, s32 size, vm::ptr<u32> number);
s32 sys_event_queue_drain(u32 event_queue_id);

s32 sys_event_port_create(vm::ptr<u32> eport_id, s32 port_type, u64 name);
s32 sys_event_port_destroy(u32 eport_id);
s32 sys_event_port_connect_local(u32 event_port_id, u32 event_queue_id);
s32 sys_event_port_disconnect(u32 eport_id);
s32 sys_event_port_send(u32 event_port_id, u64 data1, u64 data2, u64 data3);

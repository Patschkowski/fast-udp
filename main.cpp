#include <chrono>
#include <compare>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#include <gsl/util>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>

#include <winrt/base.h>

static constexpr DWORD queue_size{ 16 };
static constexpr DWORD max_outstanding{ 1 };
static constexpr DWORD max_data_buffers{ 1 };
static constexpr DWORD udp_packet_size{ 500 };

class Buffer_chopper {
public:
	explicit Buffer_chopper(RIO_BUFFERID id)
	{
		buf.BufferId = id;
		buf.Length = udp_packet_size;
		buf.Offset = 0;
	}

	RIO_BUF operator()()
	{
		auto tmp{ buf };
		buf.Offset += udp_packet_size;
		return tmp;
	}

private:
	RIO_BUF buf;
};

template<typename T>
struct Virtual_allocator {
	using value_type = T;

	Virtual_allocator() = default;

	template<typename U>
	constexpr Virtual_allocator(const Virtual_allocator<U>&) noexcept
	{
		// Do nothing.
	}

	[[nodiscard]] T* allocate(std::size_t n)
	{
		T* p{ nullptr };

		if (n > SIZE_MAX / sizeof * p) {
			throw std::bad_alloc{};
		}

		p = static_cast<T*>(VirtualAlloc(nullptr, n * sizeof * p, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!p) {
			throw std::bad_alloc{};
		}

		return p;
	}

	void deallocate(T* p, std::size_t)
	{
		VirtualFree(p, 0, MEM_RELEASE);
	}

	template<typename U>
	auto operator <=>(const Virtual_allocator<U>&) const
	{
		return std::strong_ordering::equivalent;
	}
};

static RIO_EXTENSION_FUNCTION_TABLE rio_funcs;

struct Rio_bufferid_traits {
	using type = RIO_BUFFERID;

	static void close(type value) noexcept
	{
		rio_funcs.RIODeregisterBuffer(value);
	}

	static constexpr type invalid() noexcept
	{
		return RIO_INVALID_BUFFERID;
	}
};

struct Rio_cq_traits {
	using type = RIO_CQ;

	static void close(type value) noexcept
	{
		rio_funcs.RIOCloseCompletionQueue(value);
	}

	static constexpr type invalid() noexcept
	{
		return RIO_INVALID_CQ;
	}
};

struct Socket_traits {
	using type = SOCKET;

	static void close(type value) noexcept
	{
		closesocket(value);
	}

	static constexpr type invalid() noexcept
	{
		return INVALID_SOCKET;
	}
};

struct Wsa_event_traits {
	using type = WSAEVENT;

	static void close(type value) noexcept
	{
		WSACloseEvent(value);
	}

	static constexpr type invalid() noexcept
	{
		return WSA_INVALID_EVENT;
	}
};

struct Addr_info_traits {
	using type = PADDRINFOW;

	static void close(type value) noexcept
	{
		FreeAddrInfoW(value);
	}

	static constexpr type invalid() noexcept
	{
		return nullptr;
	}
};

struct Hlocal_traits {
	using type = HLOCAL;

	static void close(type value) noexcept
	{
		LocalFree(value);
	}

	static constexpr type invalid() noexcept
	{
		return nullptr;
	}
};

using Socket_handle = winrt::handle_type<Socket_traits>;
using Wsa_event_handle = winrt::handle_type<Wsa_event_traits>;
using Rio_cq_handle = winrt::handle_type<Rio_cq_traits>;
using Rio_bufferid_handle = winrt::handle_type<Rio_bufferid_traits>;
using Addr_info_handle = winrt::handle_type<Addr_info_traits>;
using Hlocal_handle = winrt::handle_type<Hlocal_traits>;

std::wstring multi_byte_to_wide_char(std::string_view s)
{
	auto count{ MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0) };
	winrt::check_bool(count);
	const auto buf{ std::make_unique<WCHAR[]>(count) };
	count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), buf.get(), count);
	winrt::check_bool(count);
	return { buf.get(), static_cast<std::size_t>(count) };
}

int main(int argc, char** argv)
{
	try {
		if (argc >= 2 && argc <= 3) {
			auto is_sender{ false };
			std::string_view service;

			for (auto i{ 1 }; i < argc; ++i) {
				const std::string_view arg{ argv[i] };
				if (arg.starts_with("/service:")) {
					service = arg.substr(arg.find(L':') + 1);
				}
				else if (arg.starts_with("/sender")) {
					is_sender = true;
				}
			}

			// Create an IO completion port to get kernel IO notifications.
			winrt::handle iocp{ CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0) };
			if (!iocp) {
				winrt::check_win32(GetLastError());
			}

			// Initialize Winsock.
			WSADATA wsa_data;
			winrt::check_win32(WSAStartup(MAKEWORD(2, 2), &wsa_data));
			auto _{ gsl::finally([]() { WSACleanup(); }) };

			// Create a socket.
			Socket_handle socket{ WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_REGISTERED_IO) };
			if (!socket) {
				winrt::check_win32(WSAGetLastError());
			}

			// Load RIO extensions.
			{
				GUID multiple_rio = WSAID_MULTIPLE_RIO;
				DWORD bytes_returned;
				if (SOCKET_ERROR == WSAIoctl(socket.get(),
					SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
					&multiple_rio,
					sizeof multiple_rio,
					&rio_funcs,
					sizeof rio_funcs,
					&bytes_returned,
					nullptr,
					nullptr)) {
					winrt::check_win32(WSAGetLastError());
				}
			}

			// Create RIO buffers in memory.
			std::vector<CHAR, Virtual_allocator<CHAR>> memory(max_data_buffers * udp_packet_size);
			Rio_bufferid_handle registered_buffer{ rio_funcs.RIORegisterBuffer(memory.data(), static_cast<DWORD>(memory.size())) };
			if (!registered_buffer) {
				winrt::check_win32(WSAGetLastError());
			}

			std::vector<RIO_BUF> buffers(max_data_buffers);
			std::vector<PRIO_BUF> free_buffers(max_data_buffers); // Non-owning list of free buffers.
			std::generate(buffers.begin(), buffers.end(), Buffer_chopper{ registered_buffer.get() });
			std::transform(buffers.begin(), buffers.end(), free_buffers.begin(), [](auto& buf) { return &buf; });
			std::cout << "free buffers count " << free_buffers.size() << '\n';


			// Create IO completion port completion queue (from kernel to user).
			OVERLAPPED overlapped{};
			RIO_NOTIFICATION_COMPLETION nc;
			nc.Type = RIO_IOCP_COMPLETION;
			nc.Iocp.IocpHandle = iocp.get();
			nc.Iocp.CompletionKey = 0;
			nc.Iocp.Overlapped = &overlapped;
			Rio_cq_handle queue{ rio_funcs.RIOCreateCompletionQueue(queue_size, &nc) };
			if (!queue) {
				winrt::check_win32(WSAGetLastError());
			}

			// Create request queue (from user to kernel).
			// Because communication is monodirectional only one completion queue is used for send and receive.
			auto request_queue{ rio_funcs.RIOCreateRequestQueue(socket.get(),
				max_outstanding,
				max_data_buffers,
				max_outstanding,
				max_data_buffers,
				queue.get(),
				queue.get(),
				nullptr) };
			if (RIO_INVALID_RQ == request_queue) {
				winrt::check_win32(WSAGetLastError());
			}

			const auto wservice{ multi_byte_to_wide_char(service) };

			{
				struct sockaddr_in saddr;
				saddr.sin_addr.s_addr = INADDR_ANY;
				saddr.sin_family = AF_INET;
				saddr.sin_port = htons(is_sender ? 0 : (unsigned short)std::stoul(std::string{ service }));
				if (SOCKET_ERROR == bind(socket.get(), (struct sockaddr*)&saddr, sizeof(sockaddr_in))) {
					winrt::check_win32(WSAGetLastError());
				}
			}

			SOCKADDR_INET remote_address{};
			Rio_bufferid_handle registered_remote_address{ rio_funcs.RIORegisterBuffer(
				reinterpret_cast<PCHAR>(&remote_address),
				sizeof remote_address) };
			if (!registered_remote_address) {
				winrt::check_win32(WSAGetLastError());
			}
			struct sockaddr_in target;
			target.sin_family = AF_INET;
			target.sin_port = htons((unsigned short)std::stoul(std::string{ service }));
			if (1 != inet_pton(AF_INET, "127.0.0.1", &target.sin_addr)) {
				winrt::check_win32(WSAGetLastError());
			}
			std::memcpy(&remote_address, &target, sizeof target);
			RIO_BUF remote_address_buf;
			remote_address_buf.BufferId = registered_remote_address.get();
			remote_address_buf.Length = sizeof(SOCKADDR_INET);
			remote_address_buf.Offset = 0;

			auto do_it{ is_sender ? rio_funcs.RIOSendEx : rio_funcs.RIOReceiveEx };
			PRIO_BUF remote_address_ptr = is_sender ? &remote_address_buf : nullptr;
			auto increment = is_sender ? 1 : 0;

			const auto start{ std::chrono::high_resolution_clock::now() };
			constexpr auto count{ 10'000'000 };
			for (auto i = 0; i < count; i += increment) {
				winrt::check_bool((*do_it)(
					request_queue,
					free_buffers.back(),
					1,
					nullptr,
					remote_address_ptr,
					nullptr,
					nullptr,
					0,
					nullptr));

				winrt::check_win32(rio_funcs.RIONotify(queue.get()));

				// std::cout << "waiting for completion ...\n";
				DWORD transferred_bytes;
				ULONG_PTR completion_key;
				LPOVERLAPPED overlapped_ptr;
				winrt::check_bool(GetQueuedCompletionStatus(
					iocp.get(),
					&transferred_bytes,
					&completion_key,
					&overlapped_ptr,
					INFINITE));

				RIORESULT results[queue_size];
				const auto result_count{ rio_funcs.RIODequeueCompletion(queue.get(), results, ARRAYSIZE(results)) };
				switch (result_count) {
				case 0:
					// std::cout << "no results\n";
					// std::this_thread::sleep_for(std::chrono::milliseconds(500));
					break;
				case RIO_CORRUPT_CQ:
					throw std::runtime_error{ "queue corrupt" };
				default:
				{
					// TODO: Handle package in real application.
					// std::cout << "handled package\n";
					break;
				}
				}
			}
			const auto end{ std::chrono::high_resolution_clock::now() };

			// winrt::check_bool(PostQueuedCompletionStatus(iocp.get(), 0, exit_key, nullptr));
			// std::cout << "joining completion handler\n";
			// completion_handler.join();
			std::cout << count << " packages of " << udp_packet_size << " byte done in " << std::chrono::duration_cast<std::chrono::seconds>(end - start).count() << "s \n";
		}
		else {
			std::cout << "Usage " << argv[0] << " /service:<service> [/sender]\n";
		}
	}
	catch (std::exception& e) {
		std::cout << "exception " << e.what() << '\n';
	}
	catch (winrt::hresult_error& e) {
		std::cout << "exception " << winrt::to_string(e.message()) << '\n';
	}
	catch (...) {
		std::cout << "unknown exception\n";
	}

	return 0;
}

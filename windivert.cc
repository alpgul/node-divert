#include "node-windivert.h"
Napi::Object WinDivert::Init(Napi::Env env, Napi::Object exports)
{
	Napi::HandleScope scope(env);
	Napi::Function func = DefineClass(env, "WinDivert", {InstanceMethod("open", &WinDivert::open), InstanceMethod("HelperCalcChecksums", &WinDivert::HelperCalcChecksums), InstanceMethod("recv", &WinDivert::recv), InstanceMethod("send", &WinDivert::send), InstanceMethod("close", &WinDivert::close)});

	Napi::FunctionReference constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("WinDivert", func);
	return exports;
}

WinDivert::WinDivert(const Napi::CallbackInfo &info) : Napi::ObjectWrap<WinDivert>(info)
{
	std::cout << "WinDivert object created" << std::endl;
	Napi::Env env = info.Env();
	Napi::HandleScope scope(env);
	int argc = info.Length();
	if (argc < 1 || !info[0].IsString())
	{
		Napi::TypeError::New(env, "String filter expected").ThrowAsJavaScriptException();
		return;
	}
	this->filter_ = info[0].As<Napi::String>().Utf8Value();

	if (argc > 1 && info[1].IsNumber())
	{
		this->layer_ = info[1].As<Napi::Number>().Uint32Value();
	}

	if (argc > 2 && info[2].IsNumber())
	{
		this->flags_ = info[2].As<Napi::Number>().Uint32Value();
	}
	this->handle_ = INVALID_HANDLE_VALUE;
}

WinDivert::~WinDivert()
{
	std::cout << "WinDivert destructor called" << std::endl;
	this->StopThread();
	if (this->handle_ != INVALID_HANDLE_VALUE)
	{
		WinDivertClose(this->handle_);
		CloseHandle(this->handle_);
		this->handle_ = INVALID_HANDLE_VALUE;
	}
	if (this->tsfn)
	{
		this->tsfn.Release();
	}
}

Napi::Value WinDivert::recv(const Napi::CallbackInfo &info)
{
	Napi::Env env = info.Env();
	if (this->handle_ == INVALID_HANDLE_VALUE)
	{
		Napi::Error::New(env, "Filter not opened. Use open method first.").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (info.Length() < 1 || !info[0].IsFunction())
	{
		Napi::TypeError::New(env, "Function expected as argument").ThrowAsJavaScriptException();
		return env.Null();
	}
	this->tsfn = Napi::ThreadSafeFunction::New(
		env,
		info[0].As<Napi::Function>(),
		"Recv Callback",			 
		0,							 
		1							 
	);
	if (!recvThread.joinable())
	{
		this->StartThread();
	}
	return Napi::String::New(env, "Recv method executed");
}

Napi::Value WinDivert::open(const Napi::CallbackInfo &info)
{
	Napi::Env env = info.Env();
	if (this->handle_ != INVALID_HANDLE_VALUE)
	{
		Napi::Error::New(env, "Filter already opened").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	this->handle_ = WinDivertOpen(filter_.c_str(), (WINDIVERT_LAYER)layer_, 0, flags_);

	if (this->handle_ == INVALID_HANDLE_VALUE)
	{

		DWORD errorCode = GetLastError();
		std::string errorMsg = "Error opening filter: [" + std::to_string(errorCode) + "] ";
		LPWSTR errorMsgBuffer;
		FormatMessageW(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			errorCode,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPWSTR)&errorMsgBuffer,
			0,
			NULL);

		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		errorMsg += converter.to_bytes(errorMsgBuffer);
		LocalFree(errorMsgBuffer);

		if (errorCode == 2)
		{
			errorMsg += "The driver files WinDivert32.sys or WinDivert64.sys were not found.\n";
		}
		else if (errorCode == 654)
		{
			errorMsg += "An incompatible version of the WinDivert driver is currently loaded.\n"
						"Please unload it with the following commands ran as administrator:\n\n"
						"sc stop windivert\n"
						"sc delete windivert\n"
						"sc stop windivert14\n"
						"sc delete windivert14\n";
		}
		else if (errorCode == 1275)
		{
			errorMsg += "This error occurs for various reasons, including:\n"
						"the WinDivert driver is blocked by security software; or\n"
						"you are using a virtualization environment that does not support drivers.\n";
		}
		else if (errorCode == 1753)
		{
			errorMsg += "This error occurs when the Base Filtering Engine service has been disabled.\n"
						"Enable Base Filtering Engine service.\n";
		}
		else if (errorCode == 577)
		{
			errorMsg += "Could not load driver due to invalid digital signature.\n"
						"Windows Server 2016 systems must have secure boot disabled to be \n"
						"able to load WinDivert driver.\n"
						"Windows 7 systems must be up-to-date or at least have KB3033929 installed.\n"
						"https://www.microsoft.com/en-us/download/details.aspx?id=46078\n\n"
						"WARNING! If you see this error on Windows 7, it means your system is horribly "
						"outdated and SHOULD NOT BE USED TO ACCESS THE INTERNET!\n"
						"Most probably, you don't have security patches installed and anyone in your LAN or "
						"public Wi-Fi network can get full access to your computer (MS17-010 and others).\n"
						"You should install updates IMMEDIATELY.\n";
		}

		Napi::TypeError::New(env, errorMsg).ThrowAsJavaScriptException();
		return env.Undefined();
	}
	return env.Undefined();
}

Napi::Value WinDivert::HelperCalcChecksums(const Napi::CallbackInfo &info)
{
	Napi::Env env = info.Env();
	Napi::HandleScope scope(env);
	WINDIVERT_ADDRESS addr;
	int argc = info.Length();
	if (argc < 2 || !info[0].IsObject() || !info[1].IsNumber())
	{
		Napi::TypeError::New(env, "Invalid arguments.  Expected usage: HelperCalcChecksums({packet: Buffer, ...}, number)").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	Napi::Object packetData = info[0].As<Napi::Object>();
	Napi::Buffer<char> packet = packetData.Get("packet").As<Napi::Buffer<char>>();
	UINT64 flags = static_cast<UINT64>(info[1].As<Napi::Number>().DoubleValue());
	BOOL checksum = WinDivertHelperCalcChecksums(packet.Data(), packet.Length(), &addr, flags);
	if (checksum != 1)
	{
		DWORD errorCode = GetLastError();
		std::string errorMsg = "Checksum calculation failed with error code: " + std::to_string(errorCode);
		Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
		return env.Undefined();
	}
	Napi::Object checksumObject = Napi::Object::New(env);

	checksumObject.Set("UDPChecksum", Napi::Number::New(env, addr.UDPChecksum));
	checksumObject.Set("TCPChecksum", Napi::Number::New(env, addr.TCPChecksum));
	checksumObject.Set("IPChecksum", Napi::Number::New(env, addr.IPChecksum));

	return checksumObject;
}

Napi::Value WinDivert::send(const Napi::CallbackInfo &info)
{
	Napi::Env env = info.Env();
	if (this->handle_ == INVALID_HANDLE_VALUE)
	{
		Napi::Error::New(env, "Filter not opened. Use open method first.").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	int argc = info.Length();
	if (argc <= 0 || !info[0].IsObject())
	{
		Napi::TypeError::New(env, "Object expected").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	Napi::Object packetData = info[0].As<Napi::Object>();
	Napi::Buffer<char> packet = packetData.Get("packet").As<Napi::Buffer<char>>();
	Napi::Buffer<char> addrBuffer = packetData.Get("addr").As<Napi::Buffer<char>>();

	if (addrBuffer.Length() < (sizeof(WINDIVERT_ADDRESS) - 64))
	{
		Napi::TypeError::New(env, "Invalid addr buffer size").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	const WINDIVERT_ADDRESS *addr = reinterpret_cast<const WINDIVERT_ADDRESS *>(addrBuffer.Data());
	UINT pSendLen;
	BOOL send = WinDivertSend(this->handle_, packet.Data(), packet.Length(), &pSendLen, addr);
	if (send != 1)
	{
		DWORD errorCode = GetLastError();
		std::string errorMsg = "Packet send failed with error code: " + std::to_string(errorCode);
		Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
		return env.Undefined();
	}

	return Napi::Boolean::New(env, send);
}

Napi::Value WinDivert::close(const Napi::CallbackInfo &info)
{
	Napi::Env env = info.Env();
	if (this->handle_ == INVALID_HANDLE_VALUE)
	{
		Napi::Error::New(env, "Filter not opened. Use open method first.").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	this->StopThread();

	BOOL close = WinDivertClose(this->handle_);
	if (close != 1)
	{
		DWORD errorCode = GetLastError();
		std::string errorMsg = "WinDivert close failed with error code: " + std::to_string(errorCode);
		Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
		return env.Undefined();
	}
	if (this->handle_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(this->handle_);
		this->handle_ = INVALID_HANDLE_VALUE; 
	}
	return Napi::Boolean::New(env, close);
}
void WinDivert::StopThread()
{
	if (this->recvThread.joinable())
	{
		this->closeFlag = 1;
		recvThread.join();	
		if (this->tsfn)
		{
			this->tsfn.Release();
		}
	}
}
void WinDivert::StartThread()
{
	if (this->recvThread.joinable())
	{
		std::cout << "Thread is already running." << std::endl;
		return;
	}

	this->closeFlag = 0;
	try
	{
		this->recvThread = std::thread(&WinDivert::ThreadFunction, this);
	}
	catch (const std::system_error &e)
	{
		std::cerr << "Error starting thread: " << e.what() << std::endl;
		return;
	}
}

void WinDivert::ThreadFunction()
{
	char packet[MAXBUF];
	WINDIVERT_ADDRESS addr;

	while (true)
	{
		if (this->closeFlag == 1)
		{
			break;
		}
		if (this->handle_ == INVALID_HANDLE_VALUE)
		{
			std::cout << "Filter not found!" << std::endl;

			break;
		}
		UINT packetLen;
		BOOL recv = WinDivertRecv(this->handle_, packet, sizeof(packet), &packetLen, &addr);

		if (recv != 1)
		{
			DWORD error = GetLastError();

			std::string errorMsg = "Warning: Failed to read packet. Error code: " + std::to_string(error);

			std::cerr << errorMsg << std::endl;

			continue;
		}
		auto callback = [packet, packetLen, addr](Napi::Env env, Napi::Function jsCallback)
		{
			Napi::Buffer<char> packetBuffer = Napi::Buffer<char>::Copy(env, packet, packetLen);
			Napi::Buffer<char> addrBuffer = Napi::Buffer<char>::Copy(
				env, reinterpret_cast<const char *>(&addr), sizeof(WINDIVERT_ADDRESS));

			jsCallback.Call({packetBuffer, addrBuffer});
		};
		napi_status status = tsfn.BlockingCall(callback);
		if (status != napi_ok)
		{
			std::cerr << "Warning: Failed to call JavaScript callback. NAPI status: " << status << std::endl;
			break;
		}
	}
	
	if (this->tsfn)
	{
		tsfn.Release(); 
	}
	if (recvThread.joinable())
	{
		recvThread.join();
	}
}

Napi::Object InitAll(Napi::Env env, Napi::Object exports)
{
	return WinDivert::Init(env, exports);
}
NODE_API_MODULE(addon, InitAll)
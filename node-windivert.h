#ifndef WINDIVERT_H_
#define WINDIVERT_H_

#define NAPI_VERSION 4
#include <napi.h>
#include <iostream>
#include "windivert.h"
#include <thread>
#include <atomic>
#include <codecvt>

#define MAXBUF  WINDIVERT_MTU_MAX

using namespace std;

class WinDivert : public Napi::ObjectWrap<WinDivert> {
	public:
		static Napi::Object Init(Napi::Env env, Napi::Object exports);
		WinDivert(const Napi::CallbackInfo& info);
		virtual ~WinDivert();
	private:
		Napi::Value open(const Napi::CallbackInfo& info);
		Napi::Value recv(const Napi::CallbackInfo& info);
		Napi::Value close(const Napi::CallbackInfo& info);
		Napi::Value WinDivert::send(const Napi::CallbackInfo& info);
		Napi::Value WinDivert::HelperCalcChecksums(const Napi::CallbackInfo& info);

		void StartThread();
		void StopThread();
		void ThreadFunction();
		
		string filter_;
		UINT32 flags_;
		UINT32 layer_;
		HANDLE handle_;

		Napi::ThreadSafeFunction tsfn;
		std::thread recvThread;
		std::atomic<int> closeFlag;				
};
#endif
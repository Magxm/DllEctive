#include "plugin.h"

#include <ios>
#include <regex>
#include <set>
#include <sstream>
#include <string>

using namespace Script;

std::vector<Module::ModuleInfo> GetAllModules()
{
    //Now we get a list of all modules
	BridgeList<Module::ModuleInfo> modulesRaw;
    if(!Module::GetList(&modulesRaw))
    {
        _plugin_logputs("Module::GetList failed...");
        return {};
    }

    std::vector<Module::ModuleInfo> modules;
    modules.reserve(modulesRaw.Count());
    for (int i = 0; i < modulesRaw.Count(); i++)
    {
		modules.push_back(modulesRaw[i]);
    }

    return modules;
}

std::vector<Symbol::SymbolInfo> GetAllSymbols()
{
    //Now we get a list of all modules
	BridgeList<Symbol::SymbolInfo> symbolsRaw;
	if (!Symbol::GetList(&symbolsRaw))
	{
		_plugin_logputs("Symbol::GetList failed...");
		return {};
	}

	std::vector<Symbol::SymbolInfo> symbols;
	BridgeList<Symbol::SymbolInfo>::ToVector(&symbolsRaw, symbols, true);
	return symbols;
 	
}

std::vector<Module::ModuleExport> GetExports(const Module::ModuleInfo& module)
{
    BridgeList<Module::ModuleExport> exportsRaw;
    if (!GetExports(&module, &exportsRaw))
    {
        _plugin_logputs("Module::GetExports failed...");
		return {};
	}

    std::vector<Module::ModuleExport> exportsVector;
    exportsVector.reserve(exportsRaw.Count());
    for (int i = 0; i < exportsRaw.Count(); i++)
    {
		exportsVector.push_back(exportsRaw[i]);
    }

	return exportsVector;
}

std::vector<THREADALLINFO> GetAllThread()
{
    THREADLIST threadList = { 0, nullptr, 0};
    DbgGetThreadList(&threadList);

    std::vector<THREADALLINFO> threadsVector;
    threadsVector.reserve(threadList.count);

    for (int i = 0; i < threadList.count; i++)
    {
        threadsVector.push_back(threadList.list[i]);
    }

    BridgeFree(threadList.list);

	return threadsVector;
}

static bool ShouldTraceDll(const Module::ModuleInfo& module)
 {
    static const std::vector<const char*> dllsToTrace = { "ntdll.dll", "kernel32.dll"};
    for (auto& dllToTrace : dllsToTrace)
    {
    	if (strcmp(module.name, dllToTrace) == 0){
    		return true;
		}
	}

    return false;
 }

static std::string RemoveWhitespace(const std::string& str) {
    std::string result;
    for (char c : str) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            result += c;
        }
    }
    return result;
}

static std::string ToLower(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        result += std::tolower(static_cast<unsigned char>(c));
    }
    return result;
}

static bool ShouldTraceFunction(std::string functionName)
{
	
    // Preprocess the input function name: remove whitespace and convert to lowercase
    //std::string processedFunctionName = ToLower(RemoveWhitespace(functionName));

    //for (const auto& functionToTrace : functionsToTrace) {
    //    // Preprocess each string in the vector similarly before comparison
    //    if (processedFunctionName == ToLower(RemoveWhitespace(functionToTrace))) {
    //        return true;
    //    }
    //}

    //return false;

	auto lowerFunctionName = ToLower(functionName);

	// We ignore some functions that are called a lot
	if (functionName == "RtlEnterCriticalSection" || functionName == "RtlLeaveCriticalSection" || functionName == "GetCurrentThreadId" || functionName == "FindNextFileW")
	{
		return false;
	}

	if (lowerFunctionName.find("lock") != std::string::npos)
	{
		return false;
	}

	// We return true if the function name contains:
	// Memory, Virtual, Process, File, Thread, Context, Map, Read, Write
	// We do not care about the case of the function name

	
	if (lowerFunctionName.find("memory") != std::string::npos ||
				lowerFunctionName.find("virtual") != std::string::npos ||
				lowerFunctionName.find("file") != std::string::npos ||
				lowerFunctionName.find("context") != std::string::npos ||
				lowerFunctionName.find("map") != std::string::npos ||
				lowerFunctionName.find("open") != std::string::npos ||
				lowerFunctionName.find("process") != std::string::npos ||
				lowerFunctionName.find("read") != std::string::npos ||
				lowerFunctionName.find("write") != std::string::npos)
	{
				return true;
	}

	return false;
}

static std::vector<Module::ModuleExport> GetExportsToTrace(const Module::ModuleInfo& module)
{
	auto result = std::vector<Module::ModuleExport>();
	auto exports = GetExports(module);
	for (int i = 0; i < (int)exports.size(); i++)
	{
        auto& export_ = exports[i];
		if (!ShouldTraceFunction(export_.name))
		{
			dprintf("TradeDLLCalls: Skipping %s (%d/%d)\n", export_.name, i + 1, (int)exports.size());
			continue;
		}

		result.push_back(export_);
	}

	return result;
}
duint _StartAddress;
duint _EndAddress;
bool _Active = false;
bool _Tracing = false;
std::unordered_map<duint, std::string> _BreakpointedFunctions;
std::unordered_map<duint, int> _CallCount;
std::vector<std::string> _Trace;
std::vector<DWORD> _SuspendedThreads;
DWORD32 _TracedThreadId = 0;

//enum ParameterType : unsigned char
//{
//	ParameterType_BOOL,
//	ParameterType_CHAR,
//	ParameterType_UNSIGNED_CHAR,
//	ParameterType_SHORT,
//	ParameterType_UNSIGNED_SHORT,
//	ParameterType_INT,
//	ParameterType_UNSIGNED_INT,
//	ParameterType_INT64,
//	ParameterType_UNSIGNED_INT64,
//	ParameterType_CSTRING,
//	ParameterType_CWSTRING,
//};
//
//struct FunctionSignature
//{
//	std::string Name;
//	std::vector<std::string> Parameters;
//	std::vector<ParameterType> ParameterTypes;
//	ParameterType ReturnType;
//};

//static const std::unordered_map<std::string, FunctionSignature> _FunctionSignatures = {
//	{"NtCreateFile", {"NtCreateFile", {"FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "CreateDisposition", "CreateOptions", "EaBuffer", "EaLength"}, {ParameterType_UNSIGNED_INT64, ParameterType_INT, ParameterType_UNSIGNED_INT64, ParameterType_UNSIGNED_INT64, ParameterType_UNSIGNED_INT64,ParameterType_UNSIGNED_INT,ParameterType_UNSIGNED_INT, ParameterType_UNSIGNED_INT, ParameterType_UNSIGNED_INT, ParameterType_UNSIGNED_INT64, ParameterType_UNSIGNED_INT}, ParameterType_INT}}
//};
//
//
//static std::string GetParameterValuesFromCurrentRegistersOfCallForTrace(const std::string functionName)
//{
//	//We need to know the function signature to get the parameters
//	auto signature = _FunctionSignatures.find(functionName);
//	if (signature == _FunctionSignatures.end())
//	{
//		return "Unknown";
//	}
//	// registers
//	REGDUMP parameter;
//	REGDUMP regs;
//
//	if (!DbgGetRegDumpEx(&regs, sizeof(regs))) {
//	    dprintf("Read registers failed!");
//	    return "ERROR";
//	  }
//
//	//Get the parameter values from the current registers
//	std::string result;
//	for (int i = 0; i < (int)signature->second.Parameters.size(); i++)
//	{
//		auto parameter = signature->second.Parameters[i];
//		auto parameterType = signature->second.ParameterTypes[i];
//
//		auto registerValue = GetRegisterValue(parameter);
//		//We get the register based on i
//		switch(parameterType)
//		{
//			
//
//		}
//
//	}
//	
//}


static void PrintUsage()
{
	dprintf("TraceDLLCalls: Usage: traceDllCalls <startAddress>, <endAddress>\n");
}


static void SetBreakpoint(duint address, const std::string& name, bool reloadGUI = false)
{
	char command[256] = "";
    const char* reloadGUIText = reloadGUI ? "1" : "0";

    sprintf_s(command, "bp %p, %s, long, %s", address, name.c_str(), reloadGUIText);
    //dprintf("Executing command %s\n", command);
    DbgCmdExecDirect(command);
}

static void RemoveBreakpoint(duint address)
{
	char command[128] = "";
	sprintf_s(command, "bc %p", address);
	DbgCmdExecDirect(command);
}

static void ContinueProgram()
{
	DbgCmdExecDirect("erun");
}

static void Reset()
{
	_StartAddress = 0;
	_EndAddress = 0;

    for (auto& breakpointedFunction : _BreakpointedFunctions)
    {
    	Debug::DeleteBreakpoint(breakpointedFunction.first);
	}
	_BreakpointedFunctions.clear();

    RemoveBreakpoint(_StartAddress);
    RemoveBreakpoint(_EndAddress);
	_CallCount.clear();
	_Trace.clear();

	auto threads = GetAllThread();
    for (auto& thread : threads)
    {
        for (auto& suspendedThread : _SuspendedThreads)
        {
            if (suspendedThread == thread.BasicInfo.ThreadId)
            {
            	//We suspended it, so we also need to resume it
                ResumeThread(thread.BasicInfo.Handle);
				break;
			}
		}
    }
	_SuspendedThreads.clear();

	_TracedThreadId = 0;

	_Active = false;
	_Tracing = false;
}

static bool TraceDLLCalls(int argc, char** argv)
{
    dprintf("TraceDLLCalls(argc: %d, argv: %p)\n", argc, argv);

    if ( _Active)
    {
    	dprintf("TraceDLLCalls: Already active\n");
		return false;
	}
	if (argc != 3)
    {
        dprintf("TraceDLLCalls: Invalid number of arguments\n");
    	PrintUsage();
        return false;
	}

	unsigned int x;   
	std::stringstream ss;
	ss << std::hex << argv[1];
	ss >> _StartAddress;

    ss.clear();
    ss << std::hex << argv[2];
    ss >> _EndAddress;

    _BreakpointedFunctions.clear();
    _CallCount.clear();
    _Trace.clear();

    dprintf("StartAddress: %p | EndAddress: %p\n", _StartAddress, _EndAddress);
    if (!DbgMemIsValidReadPtr(_StartAddress) || !DbgMemIsValidReadPtr(_EndAddress))
    {
    	dprintf("TraceDLLCalls: Invalid address\n");
		return false;
	}

	_Active = true;

    //Delete all breakpoints
    DbgCmdExecDirect("bpc");

    dprintf("TraceDLLCalls: Setting breakpoint at start address: %p\n", _StartAddress);
    dprintf("TraceDLLCalls: Setting breakpoint at end address: %p\n", _EndAddress);
    //We now set the breakpoint at the start address and end address
    SetBreakpoint(_StartAddress, "StartAddress", false);
    SetBreakpoint(_EndAddress, "EndAddress", true);

    //We now just return and wait until our breakpoints are hit
    return true;
}


void OnBreakpoint(CBTYPE type, void* callbackInfo)
{
	//We only handle CB_BREAKPOINT
    if (type != CB_BREAKPOINT)
		return;

    if (!_Active)
        return;

	PLUG_CB_BREAKPOINT* bpInfo = (PLUG_CB_BREAKPOINT*)callbackInfo;
    // We get the address of the breakpoint
    auto address = bpInfo->breakpoint->addr;

	//Not the thread we are tracing
	if (_Tracing && _TracedThreadId != DbgGetThreadId())
	{
		// If it is one of our breakpoints, we do want to continue
		for (auto& breakpointedFunction : _BreakpointedFunctions)
		{
			if (breakpointedFunction.first == address)
			{
				ContinueProgram();
				return;
			}
		}
		return;
	}

    // We check if that is any of our set breakpoints
    if (address == _StartAddress)
    {
	    dprintf("OnBreakpoint: Start address hit\n");

        //We suspend all threads that are not the current thread
   //     auto threads = GetAllThread();
   //     for (auto& thread : threads)
   //     {
	  //      if (thread.BasicInfo.ThreadId == DbgGetThreadId())
			//	continue;

			//dprintf("OnBreakpoint: Suspending thread %d\n", thread.BasicInfo.ThreadId);
			//SuspendThread(thread.BasicInfo.Handle);
			//_SuspendedThreads.push_back(thread.BasicInfo.ThreadId);
   //     }

    	dprintf("TraceDLLCalls: Getting all modules\n");
	    auto modules = GetAllModules();
	    dprintf("TraceDLLCalls: Found %d modules\n", modules.size());

	    for (auto& module : modules)
	    {
		    if (!ShouldTraceDll(module))
		    {
	            dprintf("TraceDLLCalls: Skipping %s\n", module.name);
			    continue;
		    }

	        dprintf("TradeDLLCalls: Setting breakpoints for %s\n", module.name);

	        // We get every exported function of the module
			auto exports = GetExportsToTrace(module);
			int i = 0;
			for (auto& export_ : exports)
			{
				dprintf("TradeDLLCalls: Setting breakpoint for %s at %p! (%d/%d) \n", export_.name, export_.va, i + 1, (int)exports.size());
				SetBreakpoint(export_.va, export_.name, i != (int)exports.size() - 1);
	            _BreakpointedFunctions[export_.va] = export_.name;
	            _CallCount[export_.va] = 0;
				i++;
			}
	    }
		_TracedThreadId = DbgGetThreadId();
		dprintf("We will trace thread %d\n", _TracedThreadId);

    	_Tracing = true;
        return;
	}

	if (address == _EndAddress)
	{
		dprintf("OnBreakpoint: End address hit\n");

		//We now print the trace
		for (auto& trace : _Trace)
		{
			dprintf("%s\n", trace.c_str());
		}

        //Reset also deleted breakpoints and resumes threads
        Reset();
        return;
    }


    //We check if we are tracing
	if (!_Tracing)
	{
		return;
	}

    // We check if the address is one of our breakpointed functions
    for (auto& entry : _BreakpointedFunctions)
    {
        if (entry.first == address)
        {
	        //We got a hit
	        dprintf("OnBreakpoint: Hit at %p (%s)\n", address, entry.second.c_str());
	        _CallCount[address]++;

            //We add the function name to the trace
	        _Trace.push_back(entry.second);

			ContinueProgram();
	        return; 
        }   
    }

}

static bool TestAPIDetection(int argc, char** argv)
{
    dprintf("TraceDLLCalls: Getting all modules\n");
    auto modules = GetAllModules();
    dprintf("TraceDLLCalls: Found %d modules\n", modules.size());

    for (auto& module : modules)
    {
	    if (!ShouldTraceDll(module))
	    {
            dprintf("TraceDLLCalls: Skipping %s\n", module.name);
		    continue;
	    }

        // We get every exported function of the module
		auto exports = GetExportsToTrace(module);
		int i = 0;
		for (auto& export_ : exports)
		{
			dprintf("TradeDLLCalls: Would set breakpoint for %s at %p! (%d/%d) \n", export_.name, export_.va, i + 1, (int)exports.size());
			i++;
		}
    }

	return true;
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    // Prefix of the functions to call here: _plugin_register
    _plugin_registercommand(pluginHandle, "traceDllCalls", TraceDLLCalls, true);
	_plugin_registercommand(pluginHandle, "traceDllCallsTestAPIDetection", TestAPIDetection, true);

    _plugin_registercallback(pluginHandle, CB_BREAKPOINT, OnBreakpoint);

    // Return false to cancel loading the plugin.
    return true;
}

// Deinitialize your plugin data here.
// NOTE: you are responsible for gracefully closing your GUI
// This function is not executed on the GUI thread, so you might need
// to use WaitForSingleObject or similar to wait for everything to close.
void pluginStop()
{
    // Prefix of the functions to call here: _plugin_unregister
	_plugin_unregistercommand(pluginHandle, "traceDllCalls");
	_plugin_unregistercommand(pluginHandle, "traceDllCallsTestAPIDetection");

    _plugin_unregistercallback(pluginHandle, CB_BREAKPOINT);

    Reset();


    dprintf("pluginStop(pluginHandle: %d)\n", pluginHandle);
}

// Do GUI/Menu related things here.
// This code runs on the GUI thread: GetCurrentThreadId() == GuiGetMainThreadId()
// You can get the HWND using GuiGetWindowHandle()
void pluginSetup()
{
    // Prefix of the functions to call here: _plugin_menu

    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);
}


// Utils

function log(message){
  send({log:'['+new Date().toISOString()+'] '+message});
}

function endsWith(str, suffix) {
  return str.indexOf(suffix, str.length - suffix.length) !== -1;
};
function read_string_param(fname, arg, length){
  if (parseInt(args[i])===0){ return null; }
  length = typeof length === 'undefined' ? 50 : length;
  try {
    if (endsWith(fname,'W')){ return Memory.readUtf16String(ptr(args[i]),50); } 
    else { return Memory.readANSIString(ptr(args[i]),50); }
  }
  catch (e){
    return e;
  }
};

//Function interceptor

/*
BOOL WINAPI WriteProcessMemory(
 _In_  HANDLE  hProcess,
 _In_  LPVOID  lpBaseAddress,
 _In_  LPCVOID lpBuffer,
 _In_  SIZE_T  nSize,
 _Out_ SIZE_T  *lpNumberOfBytesWritten
);
 * */
function i_WriteProcessMemory(fname, msg, args){
	var handle=ptr(args[0]),addr=args[1],buff=ptr(args[2]), buflen=args[3];
  msg['writemem'] = {
    time : new Date().toISOString(),
    buff : Memory.readByteArray(buff, buflen)
  };
	
}
function o_WriteProcessMemory(fname, msg, retfal){
}
/*
BOOL WINAPI CreateProcess(
  _In_opt_    LPCTSTR               lpApplicationName,
  _Inout_opt_ LPTSTR                lpCommandLine,
  _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_        BOOL                  bInheritHandles,
  _In_        DWORD                 dwCreationFlags,
  _In_opt_    LPVOID                lpEnvironment,
  _In_opt_    LPCTSTR               lpCurrentDirectory,
  _In_        LPSTARTUPINFO         lpStartupInfo,
  _Out_       LPPROCESS_INFORMATION lpProcessInformation
);
*/
function i_CreateProcess(fname, msg, args){
	var process_info = ptr(args[9]);
  this.proc_pid=0;//buff;
}
function o_CreateProcess(fname, msg, retfal){
}

// Code

var exportcallbacks = {};
exportcallbacks.onMatch = function (mod){
  var fname = mod.name;
  if (/^WriteProcessMemory/.test(mod.name) ){
    log('hooking '+fname);
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        i_WriteProcessMemory(fname, c, args);
      },
      onLeave: function(retval){ 
        var c = {t:new Date().toISOString(), f:fname};
        o_WriteProcessMemory(fname, c, retval);
        send(c);
        return retval; 
      }
    });
    return;
  } 
};
exportcallbacks.onComplete = function (){};

var modulecallbacks={};
modulecallbacks.onMatch = function (module){
  Module.enumerateExports( module.name, exportcallbacks );  
  return;
};
modulecallbacks.onComplete = function (){
  log('module enumeration done');
  return;
};

// Main
Process.enumerateModules( modulecallbacks );


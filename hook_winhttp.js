
// Utils
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

function i_WinHttpOpenRequest(fname, msg, args){
  var conn = ptr(args[0]) ;    // HINTERNET hConnect,
  var method = ptr(args[1]);   // LPCWSTR pwszVerb,
  var objname = ptr(args[2]);  // LPCWSTR pwszObjectName,
  var version = ptr(args[3]);  // LPCWSTR pwszVersion,
  var referrer = ptr(args[4]); // LPCWSTR pwszReferrer,
  //_In_  LPCWSTR *ppwszAcceptTypes,
  //_In_  DWORD dwFlags
  msg.http_prep_req = {
    method : read_string_param(fname, method),
    referrer : read_string_param(fname, referrer),
    objname : read_string_param(fname, objname)
  };
};
function i_WinHttpSendRequest(fname, msg, args){
  var hreq = ptr(args[0]);    // HINTERNET hRequest
  var headers = ptr(args[1]); // LPCWSTR
  var headers_len = args[2];
  var optional= args[3];      // LPVOID 
  var optional_len = args[4];
  var total_len =  args[5];
  var content = args[6];      // DWORD_PTR
  msg.http_req = {
    time : new Date().toISOString(),
    head : read_string_param(fname, headers, parseInt(headers_len)),
    body : read_string_param(fname, content, parseInt(total_len))
  };
};
function i_WinHttpConnect(fname, msg, args){
  var hsession = ptr(args[0]);  // HINTERNET  hSession
  var srvname = ptr(args[1]);   // LPCWSTR pswzServerName
  var port = parseInt(args[2]); // INTERNET_PORT nServerPort
  msg.http_con = {
    time : new Date().toISOString(),
    dest : read_string_param(fname, srvname) +':'+port
  };
};
function o_WinWinHttpReadData(fname, msg, args){
  //  _In_   HINTERNET hRequest,
  //  _Out_  LPVOID lpBuffer,
  //  _In_   DWORD dwNumberOfBytesToRead,
  //  _Out_  LPDWORD lpdwNumberOfBytesRead
  // TODO
  msg.http_resp = {
    time : new Date().toISOString(),
  };
};

// Code
var exportcallbacks = {};
exportcallbacks.onMatch = function (mod){
  if (/Http/.test(mod.name) ){
    var fname = mod.name;
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        var c = {t:new Date().toISOString(), f:fname};
        switch (true){
          case /HttpSendRequest/.test(fname):
          send({log:'['+new Date().toISOString()+'] hooking HttpsendRequest.'});
          i_WinHttpSendRequest(fname, c, args);
          break;
          case /HttpOpenRequest/.test(fname):
          send({log:'['+new Date().toISOString()+'] hooking HttpOpenRequest.'});
          i_WinHttpOpenRequest(fname, c, args);
          break;
          case /HttpConnect/.test(fname):
          send({log:'['+new Date().toISOString()+'] hooking HttpConnect.'});
          i_WinHttpConnect(fname, c, args);
          break;                    
          default:
          //for(var i=0; i<10; i++){ c['args_'+i] = read_string_param(fname, args[i]); };
          break;
        }
        send(c);
      },
      onLeave: function(retval){ 
        // TODO: hook on exit
        return retval; 
      }
    });
  }
};
exportcallbacks.onComplete = function (){};

var modulecallbacks={};
modulecallbacks.onMatch = function (module){
  Module.enumerateExports(module.name, exportcallbacks );  
  return;
};
modulecallbacks.onComplete = function (){
  send({log:'['+new Date().toISOString()+'] module enumeration done.'});
  return;
};

// Main
Process.enumerateModules( modulecallbacks );


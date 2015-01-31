
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
function i_WinHttpReadData(fname, msg, args){
  //  _In_   HINTERNET hRequest,
  var buff  = ptr(args[1]); //  _Out_  LPVOID lpBuffer,
  //  _In_   DWORD dwNumberOfBytesToRead,
  var pbufflen = ptr(args[3]); //  _Out_  LPDWORD lpdwNumberOfBytesRead
  this.http_WinHttpReadData_buff = buff;
  this.http_WinHttpReadData_pbufflen = pbufflen;
};
function o_WinHttpReadData(fname, msg, retfal){
  //  _In_   HINTERNET hRequest,
  //  _Out_  LPVOID lpBuffer,
  //  _In_   DWORD dwNumberOfBytesToRead,
  //  _Out_  LPDWORD lpdwNumberOfBytesRead
  // TODO
  var buff = this.http_WinHttpReadData_buff;
  var pbufflen = this.http_WinHttpReadData_pbufflen;
  msg.http_resp = {
    time : new Date().toISOString(),
    resp : Memory.readByteArrat(buff, Memory.readU32(pbufflen) )
  };
};

// Code

var exportcallbacks = {};
exportcallbacks.onMatch = function (mod){
  var fname = mod.name;
  if (/^HttpSendRequest/.test(mod.name) ){
    log('hooking '+fname);
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        var c = {t:new Date().toISOString(), f:fname};
        i_WinHttpSendRequest(fname, c, args);
        send(c);
      },
      onLeave: function(retval){ 
        return retval; 
      }
    });
    return;
  } 
  if (/^HttpOpenRequest/.test(mod.name) ){
    log('hooking '+fname);
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        var c = {t:new Date().toISOString(), f:fname};
        i_WinHttpOpenRequest(fname, c, args);
        send(c);
      },
      onLeave: function(retval){ 
        return retval; 
      }
    });
    return;
  } 
  if (/^HttpConnect/.test(mod.name) ){
    log('hooking '+fname);
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        var c = {t:new Date().toISOString(), f:fname};
        i_WinHttpConnect(fname, c, args);
        send(c);
      },
      onLeave: function(retval){ 
        return retval; 
      }
    });
    return;
  } 
  if (/^HttpReadData/.test(mod.name) ){
    log('hooking '+fname);
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        i_WinHttpReadData(fname, c, args);
      },
      onLeave: function(retval){ 
        var c = {t:new Date().toISOString(), f:fname};
        o_WinHttpReadData(fname, c, retval);
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


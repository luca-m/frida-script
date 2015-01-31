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

function i_CryptEncrypt(fname, msg, args){
  // _In_     HCRYPTKEY hKey, //TODO: extract key http://edc.tversu.ru/elib/inf/0088/0596003943_secureprgckbk-chp-5-sect-27.html
  // _In_     HCRYPTHASH hHash,
  // _In_     BOOL Final,
  // _In_     DWORD dwFlags,
  var pdata = ptr(args[4]);   // _Inout_  BYTE *pbData,
  var pdatalen = Memory.readU32(ptr(arts[5])); // _Inout_  DWORD *pdwDataLen,
  // _In_     DWORD dwBufLen 
  msg.cry_e = {
    time : new Date().toISOString(),
    data : Memody.readByteArray(pdata,pdatalen)
  };
};
function i_CryptDecrypt(fname, msg, args){
  // _In_     HCRYPTKEY hKey, //TODO: extract key http://edc.tversu.ru/elib/inf/0088/0596003943_secureprgckbk-chp-5-sect-27.html
  // _In_     HCRYPTHASH hHash,
  // _In_     BOOL Final,
  // _In_     DWORD dwFlags,
  // _Inout_  BYTE *pbData,
  // _Inout_  DWORD *pdwDataLen
  this.crypto_CryptDecrypt_buff = ptr(args[4]);
  this.crypto_CryptDecrypt_pbufflen = ptr(args[5]);
}
function o_CryptDecrypt(fname, msg, retval){
  msg.cry_d = {
    time : new Date().toISOString(),
    data : Memody.readByteArray(this.crypto_CryptDecrypt_buff, Memory.readU32(this.crypto_CryptDecrypt_pbufflen))
  };
}

function i_CryptMsgUpdate(fname, msg, args){
  // _In_  HCRYPTMSG hCryptMsg,
  var pbdata = ptr(args[1]);      // _In_  const BYTE *pbData,
  var cbdata = parseInt(args[2]); // _In_  DWORD cbData,
  // _In_  BOOL fFinal
  // TODO: check if is encoding or decoding 
  msg.cry_enc = {
    time : new Date().toISOString(),
    data : Memody.readByteArray(pbdata)
  };
};
function i_CryptGenKey(fname, msg, args){
  //  _In_   HCRYPTPROV hProv,
  //  _In_   ALG_ID Algid,
  //  _In_   DWORD dwFlags,
  //  _Out_  HCRYPTKEY *phKey
  this.crypto_CryptGenKey_phkey = ptr(args[3]);
}
function o_CryptGenKey(fname, msg, retval){
  // TODO: retrieve the generated key
  //       extract key http://edc.tversu.ru/elib/inf/0088/0596003943_secureprgckbk-chp-5-sect-27.html
  msg.cry_key = {
    time : new Date().toISOString(),

  };
};

// Code

var exportcallbacks = {};
exportcallbacks.onMatch = function (mod){
  var fname = mod.name;
  if (/^CryptEncrypt$/.test(mod.name) ){
    log('hooking '+fname);
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        var c = {t:new Date().toISOString(), f:fname};
        i_CryptEncrypt(fname, c, args);
        send(c);
      },
      onLeave: function(retval){ 
        return retval; 
      }
    });
    return;
  } 
  if (/^CryptDecrypt$/.test(mod.name) ){
    log('hooking '+fname);
    Interceptor.attach(ptr(mod.address), {
      onEnter: function(args) {
        //var c = {t:new Date().toISOString(), f:fname};
        i_CryptDecrypt(fname, c, args);
        //send(c);
      },
      onLeave: function(retval){ 
        log('hooking CryptDecrypt (OUT)');
        o_CryptDecrypt(fname, c, retval);
        return retval; 
      }
    });
    return;
  } 
};
exportcallbacks.onComplete = function (){};

var modulecallbacks={};
modulecallbacks.onMatch = function (module){
  log('module:'+module.name)
  Module.enumerateExports(module.name, exportcallbacks );  
  return;
};
modulecallbacks.onComplete = function (){
  log('module enumeration done');
  return;
};

// Main
Process.enumerateModules( modulecallbacks );



// Utils

function log(message){
  send({log:'['+new Date().toISOString()+'] '+message});
}
function endsWith(str, suffix) {
  return str.indexOf(suffix, str.length - suffix.length) !== -1;
};
function read_string_param(fname, arg, length){
  if (parseInt(arg)===0){ return null; }
  length = typeof length === 'undefined' ? 50 : length;
  try {
    if (endsWith(fname,'W')){ return Memory.readUtf16String(ptr(arg), length); } 
    else { return Memory.readAnsiString(ptr(arg), length); }
  }
  catch (e){
    return e;
  }
};

// Vars

var pattern = '%(pattern)s';

// Code

function match_found (address, size){
	var data =read_string_param('A',address, -1);
	send({ time:new Date().toISOString(),
         addr:address.toInt32(), 
         data:data });
}

function scan_memory(){
  log('starting memory');
	Process.enumerateRanges('rw-', {
		onMatch: function onMatch(range){
			Memory.scan(range.base, range.size, pattern, {
				onMatch: match_found,
				onError: function onError(reason){},
				onComplete: function onComplete(){}
			})
		},
		onComplete: function onComplete(){
      log('memory scan completed');
    }
	});
	
	
}
// Main

var scan_timer = setTimeout(scan_memory, %(msecs)d )



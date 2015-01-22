import frida
import sys
import argparse
import signal
from collections import defaultdict

CHUNKS = defaultdict(set)

def prepare_script(frida_target_process, pattern, time):
    with open('mondump.js','r') as f:
        return frida_target_process.session.create_script(f.read()%{'pattern':pattern.encode('hex'), 'msecs':time})

def on_frida_message(msg, data , chunks = CHUNKS):
    if msg['payload'].has_key('addr') and msg['payload'].has_key('time') and msg['payload'].has_key('data'): 
        chunks[msg['payload']['addr']].add(msg['payload']['data'])
        return
    if msg['payload'].has_key('log'):
        print(msg['payload']['log'])
        return

def pretty_print_chunks (chunks , file=sys.stdout):
    for addr,strs in chunks.items():
        print >> file, '@{}:'.format(hex(addr))
        for s in strs:
            try:
                print >> file, unicode(s.encode('ascii','ignore'))
            except Exception,e:
                print >> file, [c for c in s]

def signal_handler(signal, frame):
    print 'Removing TAPs and writing to %s' % ofile
    script.unload()
    with open(ofile,'w') as f:
        pretty_print_chunks(CHUNKS, file=f)
    sys.exit(0)

def main():
    global script
    global ofile
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="target PID")
    parser.add_argument("-p", "--pattern", default='HTTP', help="Pattern to match,(AAABBBXXXWW , wildchar ? not yet supported)")
    parser.add_argument("-t", "--time", default=5000, help="Periodic memory scan time in msec")
    parser.add_argument("-o", "--outfile", default='dump.txt', help="Output File where to put captured strings")
    
    args = parser.parse_args()

    process = frida.attach(args.pid)
    ofile = args.outfile
    script = prepare_script(process, args.pattern, args.time)
    script.on('message', on_frida_message)
    
    script.load()
    signal.signal(signal.SIGINT, signal_handler)
        
    while True:
        inp = sys.stdin.readline()
        pretty_print_chunks(CHUNKS)

if __name__ == '__main__':
    main()

import frida
import sys
import argparse

def prepare_hook_script(frida_target_process):
    with open('hook_winhttp.js','r') as f:
        return frida_target_process.session.create_script(f.read())

def on_frida_message(msg, data , chunks = CHUNKS):
    if msg['payload'].has_key('http_req'):
        print("[{}] HTTP REQUEST".format(msg['payload']['http_req']['time']))
        print("HEADER:\n {}".format(msg['payload']['http_req']['head'])) 
        print("BODY:\n {}".format(msg['payload']['http_req']['body'])) 
        return
    if msg['payload'].has_key('http_prep_req'):
        print("[{}] PREPARING HTTP {}".format(msg['payload']['http_prep_req']['time'],msg['payload']['http_prep_req']['method']))
        print("REFERRER:\n {}".format(msg['payload']['http_prep_req']['referrer'])) 
        print("OBJNAME:\n {}".format(msg['payload']['http_prep_req']['objname'])) 
        return
    if msg['payload'].has_key('http_con'):
        print("[{}] HTTP CONNECT".format(msg['payload']['http_con']['time']))
        print("DESTINATION:\n {}".format(msg['payload']['http_con']['dest'])) 
        return
    else:
        print(msg)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="target PID")
    args = parser.parse_args()
    process = frida.attach(args.pid)
    script = prepare_hook_script(process)
    script.on('message', on_frida_message)
    script.load()
    sys.stdin.read() # wait

if __name__ == '__main__':
    main()

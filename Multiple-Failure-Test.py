#!/usr/bin/env python3
import os,sys,copy,random
from time import sleep, time
from datetime import datetime
from threading import Thread
from InbandController import Controller
from TestbedController import Testbed

if __name__  == "__main__":
    testbed = Testbed(sys.argv[1])
    # Initialization P4 switch
    t = []
    for sid in testbed.p4_device_information:
        testbed.network_setup(sid, 3, 1)
    sleep(1)
    for sid in testbed.p4_device_information:
        t.append(Thread(target=testbed.initialization, args=(sid, )))
        t[-1].start()
    for i in t:
        i.join()
    sleep(10)
    # If the topology is not fixed, comment Line 23-25
    for sid in testbed.p4_device_information:
        testbed.network_setup(sid, 3, 2)
        testbed.network_setup(sid, 1, 1)   
    controller = Controller(sys.argv[2], sys.argv[3])
    controller.initialization()
    sleep(5)

    t = []
    for sid in testbed.p4_device_information:
        testbed.network_setup(sid, 2, 1)
    sleep(10)

    # Setup background traffic 
    controller.network_failure_planner()
    for nodeA in controller.topology:
        for nodeB in controller.topology[nodeA]:
            if nodeA != 0 and nodeB != 0:
                hostA = testbed.p4_device_information[nodeA]["host_ip"]
                hostB = testbed.p4_device_information[nodeB]["host_ip"]
                controller.background_traffic_path_configure(hostA, hostB, nodeA, nodeB)
    
    print ("Failure detection and recovery")
    case_name = "MRT"
    random.seed(int(sys.argv[5]))
    control_failure_cases = []
    link_failure_case = []
    node_failure_case = []

    for fc in controller.control_failure_cases:
        if (type(fc) == int):
            node_failure_case.append(fc)
        else:
            link_failure_case.append(fc)
    if (sys.argv[6] == "1"):    # Link
        test_type_name = "multiple_links"
        control_failure_cases = [(142, 144), (144, 157)]
    elif (sys.argv[6] == "2"):  # Node
        test_type_name = "multiple_nodes"
        control_failure_cases = [142,147]
    fr_file = "result/%s-Algorithm_9_topology_test_type=%s_data.csv"%(case_name, test_type_name)
    try:
        sleep(5)
        # Setting failure happen time [Occurs after random_time (s)]
        controller.configuration_network_flag = False
        r = random.uniform(0.0, 0.1)
        random_time = 3+r
        random_timestamp = time()+random_time
        st = time()
        testbed.background_traffic_iperf(35, 10)
        if (sys.argv[6] == "1"): # Link
            for i in control_failure_cases:
                Thread(target=testbed.link_up_down, args=(1, i[0], i[1], random_timestamp, )).start()
        elif (sys.argv[6] == "2"): # Node
            for i in control_failure_cases:
                Thread(target=testbed.node_up_down, args=(1, i, random_timestamp, )).start()
        # Failure detection and recovery
        failure_case_id, detection_time, recovery_time = controller.failure_detection_and_recovery(-1)
        sleep(10)
        
        # Recording result to csv document
        test_case = ""
        if sys.argv[6] == "1":
            for i in control_failure_cases:
                test_case += "%d/%d|"%(i[0], i[1])
        elif sys.argv[6] == "2":
            for i in control_failure_cases:
                test_case += "%d|"%(i)
        if (detection_time == recovery_time == None):
            print("Count: %d, Testing case: %s, => Error"%((int(sys.argv[4])+1), str(control_failure_cases)))
        else: 
            print("Count: %d, Testing case: %s, => Total detection time: %.6f, Recovery time: %.6f"%((int(sys.argv[4])+1), str(control_failure_cases), (detection_time-random_time), recovery_time))
            fr_logging = open(fr_file,"a")
            fr_logging.write("%s,%s,%s,%s,%s\n"%(sys.argv[4], str(test_case), str(detection_time-random_time), str(recovery_time), str(detection_time-random_time+recovery_time)))
            fr_logging.close()
        controller.configuration_network_flag = False
    finally:
        for sid in testbed.p4_device_information:
            testbed.switch_control(2,sid)
        testbed.kill_service()
        controller.kill_controller()
        exit()
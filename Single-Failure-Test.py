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
    date_time = datetime.now().strftime("%d%m%Y_%H%M%S")
    count = int(sys.argv[4])
    random.seed(int(sys.argv[5]))
    control_failure_cases = []
    link_failure_case = []
    node_failure_case = []

    for fc in controller.control_failure_cases:
        if (type(fc) == int):
            if (len(controller.control_path_tree[fc]["nodes"]) > 0):
                node_failure_case.append(fc)
        else:
            link_failure_case.append(fc)
    if (sys.argv[6] == "1"):    # Link
        test_type_name = "link"
        control_failure_cases = link_failure_case
    elif (sys.argv[6] == "2"):  # Node
        test_type_name = "node"
        control_failure_cases = node_failure_case
        control_failure_cases = [141]
    elif (sys.argv[6] == "3"):  # All
        test_type_name = "all"
        control_failure_cases = controller.control_failure_cases
    elif (sys.argv[6] == "4"):  # Random
        test_type_name = "random"
        control_failure_cases = []
        control_case_count = len(controller.control_failure_cases)
        for i in range(count):
            case_id = random.randint(0,control_case_count-1)
            control_failure_cases.append(controller.control_failure_cases[case_id])
        count = 1
        print (control_failure_cases)
    fr_file = "result/%s_%s-Algorithm_test_type=%s_topology-detection=%s_data.csv"%(date_time, case_name, test_type_name, sys.argv[3])
    try:
        for fc in control_failure_cases:
            sleep(5)
            for f in range(len(controller.failure_cases)):
                if controller.failure_cases[f] == fc:
                    test_case_id = f
                    break
            c = 0
            while (c < count):
                # Setting failure happen time [Occurs after random_time (s)]
                controller.configuration_network_flag = False
                r = random.uniform(0.0, float(sys.argv[3]))
                random_time = 3+r
                random_timestamp = time()+random_time
                st = time()
                testbed.background_traffic_iperf(35, 10)
                if (type(controller.failure_cases[test_case_id]) == tuple): # Link
                    Thread(target=testbed.link_up_down, args=(1, controller.failure_cases[test_case_id][0], controller.failure_cases[test_case_id][1], random_timestamp, )).start()
                elif (type(controller.failure_cases[test_case_id]) == int): # Node
                    Thread(target=testbed.node_up_down, args=(1, controller.failure_cases[test_case_id], random_timestamp, )).start()
                
                # Failure detection and recovery
                failure_case_id, detection_time, recovery_time = controller.failure_detection_and_recovery(test_case_id)
                for sid in testbed.p4_device_information:
                    testbed.kill_iperf(sid)
                sleep(2)
                
                # Recording result to csv document
                if type(controller.failure_cases[test_case_id]) == int:
                    test_case = str(controller.failure_cases[test_case_id])
                elif type(controller.failure_cases[test_case_id]) == tuple:
                    test_case = "%d->%d"%(controller.failure_cases[test_case_id][0], controller.failure_cases[test_case_id][1])
                
                if (detection_time == recovery_time == failure_case_id == None):
                    print("Counter: %d, Testing case: %s, Error! "%((c+1), str(controller.failure_cases[test_case_id])))
                    exit()
                elif (failure_case_id == -1):
                    print("Counter: %d, Testing case: %s, Multiple error! "%((c+1), str(controller.failure_cases[test_case_id])))
                    exit()
                else:
                    if type(controller.failure_cases[failure_case_id]) == int:
                        detected_case = str(controller.failure_cases[failure_case_id])
                    elif type(controller.failure_cases[failure_case_id]) == tuple:
                        detected_case = "%d->%d"%(controller.failure_cases[failure_case_id][0],controller.failure_cases[failure_case_id][1])
                    print("Counter: %d, Testing case: %s, Detection case: %s => Total detection time: %.6f, Recovery time: %.6f"%((c+1), str(controller.failure_cases[test_case_id]), str(controller.failure_cases[failure_case_id]), (detection_time-random_time), recovery_time))
                    fr_logging = open(fr_file,"a")
                    fr_logging.write("%s,%s,%s,%s,%s\n"%(test_case, detected_case, str(detection_time-random_time), str(recovery_time), str(detection_time-random_time+recovery_time)))
                    fr_logging.close()
                
                # Reset testbed
                if (type(controller.failure_cases[test_case_id]) == tuple): # Link
                    testbed.link_up_down(2, controller.failure_cases[test_case_id][0], controller.failure_cases[test_case_id][1], 0)
                    controller.configuration_network_flag = False
                elif (type(controller.failure_cases[test_case_id]) == int): # Node
                    sw_id = controller.failure_cases[test_case_id]
                    testbed.node_up_down(2, controller.failure_cases[test_case_id], 0)
                    controller.configuration_network_flag = False
                    if (test_case_id == failure_case_id):
                        while (True):
                            controller.switch_discovery()
                            sleep(float(sys.argv[2]))
                            if (sw_id in controller.switch_information):
                                if (controller.switch_information[sw_id] != None):
                                    break
                if (test_case_id == failure_case_id): 
                    controller.configuration_network_flag = True
                    controller.reset_testbed(failure_case_id)
                    sleep(5)
                    if (type(controller.failure_cases[test_case_id]) == int): # Node
                        nodeA = controller.failure_cases[test_case_id]
                        hostA = testbed.p4_device_information[nodeA]["host_ip"]
                        for nodeB in controller.topology[nodeA]:
                            if nodeA != 0 and nodeB != 0:
                                hostB = testbed.p4_device_information[nodeB]["host_ip"]
                                controller.background_traffic_path_configure(hostA, hostB, nodeA, nodeB)
                        sleep(5)
                    controller.configuration_network_flag = False
                c += 1
                for sid in testbed.p4_device_information:
                    testbed.kill_iperf(sid)
                sleep(5)
    finally:
        for sid in testbed.p4_device_information:
            testbed.switch_control(2,sid)
        testbed.kill_service()
        controller.kill_controller()
        exit()
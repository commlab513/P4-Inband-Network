# P4-Inband-Network Testbed 
> This repo is for building a P4IBN Testbed. 

## System requirement:
<dl>
  <dt>Hardware:</dt>
  <dd>
    <b>CPU</b>: Intel i7 serise<br \>
    <b>RAM</b>: 16 GB<br \>
    <b>Physical interfaces</b>: 6 <br \>(1 interface for testbed control port, 5 interface for switch ports)
  </dd>
  <dt>Software:</dt>
  <dd>
    <b>Username</b>: user<br />
    <b>Password</b>: user<br />
    [You can modify the username and password, but make sure the username and password in p4-compiler.py are also updated. ]<br />
    <b>OS</b>: Ubuntu 20.04.4<br />
    <b>Python</b>: 3.8.10 <br />
  </dd>
</dl>

## Installation:
<dl>
  <dt> Controller: </dt>
  <dd>
    Install OVS from apt: sudo apt install openvswitch-switch <br />
    Install Protocol buffer, gRPC, P4Runtime: The installation refer to github (https://github.com/jafingerhut/p4-guide)
  </dd>
  <dt>P4 Switch</dt>
  <dd>
    Install Iperf from apt: sudo apt install iperf 
    Install Protocol buffer, gRPC, Behavioral Model v2 (bmv2) : The installation refer to github (https://github.com/jafingerhut/p4-guide)
  </dd>
</dl>

## Testbed Configuration
1. Modify the control IP addresses form the PM information JSON file at ./topology-profiles. 
> The control IP address is used for startup/shutdown P4 switch, and SSH connection to switches. 
2. Compile P4 switch behaviors
<br />Since the authentication code are different, the compiler helps to generate difference authentication code for each P4 switch.
<br />The swinfo.json collected all switch informatiom, it used for the controller authenticating new switches. 
> python3 ./p4-compiler.py 
3. run shell script to test system. <br />run_sft.sh for single failure test. <br />run_mft.sh for multiple failures test. 

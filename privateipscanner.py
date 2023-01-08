#! /usr/bin/python3
'''
FILE: privateipscanner.py
AUTH: Robert Gates
DATE: 8 Jan 23
DESC: examine all private ip's in a 'quick' time frame
NOTE: 

POST: I ended up choosing to use threads as I was creating subprocesses for
        nmap. Allowing for this py module to become a nmap manager of sorts.
        
    I chose to use the ipaddress in order to make handling the concept and
        use case for the IPs significantly easier on myself.
        
    I set ThreadPoolExecutor(max_workers=256) as that allowed for decent speed
        on my cpu without hindering my ability to do other tasks. I believe it
        would not be too difficult to add a check for cpu load to ensure that
        the module doesn't overload the host computer. However, I am satisfied
        with it at the moment until it infurates me and I return to refactor
        the code.
        
    I was going to change how the generators work so that it wouldn't be as
        bulky, but then again, the neat rhomboids grew on me.
        
    In the process of making this I did learn a little about using the
        carraige return '\r' to make a progress measurement.
        
    I also experimented in using Notepad++ as my text editor, I ended up running
        the module through Notepad and whenever the window would error and shut
        down, I would plug the current code into IDLE in order to examine the
        error.
        
        I have seen some say that wrapping everything in a 'try,except' is
        considered bad practice. But I feel like it may be necessary to provide
        enough feedback for editing in Notepad. 
    
    Using threading in conjuction with subprocess as a 'managment' system seems
        like a user friendly way to start parallel processing, will experiment
        with other use cases.
        
'''

# import
# ---------------------------------------------------------------------------__
from concurrent.futures import ThreadPoolExecutor as cfThreads, as_completed as cf_as_completed
from time import perf_counter as pc, time, sleep
from ipaddress import IPv4Network as ip_cidr
from datetime import datetime as dt
import subprocess as sp
import sys
# ---------------------------------------------------------------------------__

# variables
# ---------------------------------------------------------------------------__
# private network ranges
CLASS_A = ip_cidr('10.0.0.0/8')
CLASS_B = ip_cidr('172.16.0.0/12')
CLASS_C = ip_cidr('192.168.0.0/16')
# ---------------------------------------------------------------------------__

# main
# ---------------------------------------------------------------------------__


def main():
    print(dt.now())

    print('''
    Welcome to the Private IP Python scantool! Please note the following:
    
    192.168.0.0/24 is the same as               |Scan Options:
    192.168.0.0 - 192.168.0.255                 |    C:
                                                |    192.168.0.0/16 will take 60 seconds to scan
        There are 255 IPs in this range         |    
                                                |    B:
    192.168.0.0/16 is the same as               |    172.16.0.0/12 will take about 15min to scan
    192.168.0.0 - 192.168.255.255               |    
                                                |    A:
        There are 65,025 IPs in this range      |    10.0.0.0/8 will likly take about 4hrs to scan
                                                |
    172.16.0.0/12 is the same as                |    
    172.16.0.0 - 172.32.255.255                 |    
                                                |   
        There are 8,128,125 IPs in this range   |    
                                                |    
    10.0.0.0/8 is the same as                   |   
    10.0.0.0 - 10.255.255.255                   |    Do you still wish to continue?
                                                |    (input y or n)
        There are 16,581,375 IP's in this range |   
    ''')

    # user inputs
    accept = input('-->')
    while accept.lower() not in ['y', 'n']:
        accept = input('(y/n)-->')

    if accept.lower() == 'y':
        pass
    elif accept.lower() == 'n':
        sys.exit()
    else:
        print('condition check')

    print('''Scan options 
    1-scan C 
    2-scan B 
    3-scan A''')
    choice = input('-->')
    while choice not in ['1', '2', '3']:
        choice = input('(1/2/3)-->')

    # scan start
    start_time = pc()

    results = []
    with cfThreads(max_workers=256) as thread:
        threads = []
        if choice == '3':
            # generate through class a
            print('Class A 10.0.0.0/8\n')
            for a_subnets in class_a_subnet_gen():
                threads.append(thread.submit(nmap_host_discovery, a_subnets))
                print('Submitting thread for ', a_subnets,
                      threads[-1], len(threads), 'have been submitted', end='\r')

        if choice == '2':
            # generate through class b
            print('\n\nClass B 172.16.0.0/12\n')
            for b_subnets in class_b_subnet_gen():
                threads.append(thread.submit(nmap_host_discovery, b_subnets))
                print('Submitting thread for ', b_subnets,
                      threads[-1], len(threads), 'have been submitted', end='\r')

        if choice == '1':
            # generate through class c
            print('\n\nClass C 192.168.0.0/16\n')
            for c_subnets in class_c_subnet_gen():
                threads.append(thread.submit(nmap_host_discovery, c_subnets))
                print('Submitting thread for ', c_subnets,
                      threads[-1], len(threads), 'have been submitted', end='\r')

        print('\n\nAll threads have been submitted at ', dt.now())

        # all finished collect here and update
        for futures in cf_as_completed(threads):
            results.append(futures.result())
            print('Progress', len(results), '/', len(threads), end='\r')

    print('#'*50, '\nScan Report')
    for result in results:
        check = result.split('\n')
        if len(check) > 3:
            print('\n\n', result)
    print('Scan Time:', round(pc() - start_time, 6))
# ---------------------------------------------------------------------------__

# functions
# ---------------------------------------------------------------------------__


def class_a_subnet_gen() -> 'generator':
    '''
    break /8 into /24, keeping the subdivisions as ipaddr objects allows for 
    more accurate subnet ranges as needed
    '''
    for net in CLASS_A.subnets():
        for subnet0 in ip_cidr(net).subnets():
            for subnet1 in ip_cidr(subnet0).subnets():
                for subnet2 in ip_cidr(subnet1).subnets():
                    for subnet3 in ip_cidr(subnet2).subnets():
                        for subnet4 in ip_cidr(subnet3).subnets():
                            for subnet5 in ip_cidr(subnet4).subnets():
                                for subnet6 in ip_cidr(subnet5).subnets():
                                    for subnet7 in ip_cidr(subnet6).subnets():
                                        for subnet8 in ip_cidr(subnet7).subnets():
                                            for subnet9 in ip_cidr(subnet8).subnets():
                                                for subnet10 in ip_cidr(subnet9).subnets():
                                                    for subnet11 in ip_cidr(subnet10).subnets():
                                                        for subnet12 in ip_cidr(subnet11).subnets():
                                                            for subnet13 in ip_cidr(subnet12).subnets():
                                                                for subnet14 in ip_cidr(subnet13).subnets():
                                                                    yield subnet14


def class_b_subnet_gen() -> 'generator':
    '''
    break /12 into /24, keeping the subdivisions as ipaddr objects allows for 
    more accurate subnet ranges as needed
    '''
    for net in CLASS_B.subnets():
        for subnet0 in ip_cidr(net).subnets():
            for subnet1 in ip_cidr(subnet0).subnets():
                for subnet2 in ip_cidr(subnet1).subnets():
                    for subnet3 in ip_cidr(subnet2).subnets():
                        for subnet4 in ip_cidr(subnet3).subnets():
                            for subnet5 in ip_cidr(subnet4).subnets():
                                for subnet6 in ip_cidr(subnet5).subnets():
                                    for subnet7 in ip_cidr(subnet6).subnets():
                                        for subnet8 in ip_cidr(subnet7).subnets():
                                            for subnet9 in ip_cidr(subnet8).subnets():
                                                for subnet10 in ip_cidr(subnet9).subnets():
                                                    yield subnet10


def class_c_subnet_gen() -> 'generator':
    '''
    break /16 into /24, keeping the subdivisions as ipaddr objects allows for 
    more accurate subnet ranges as needed
    '''
    for net in CLASS_C.subnets():
        for subnet0 in ip_cidr(net).subnets():
            for subnet1 in ip_cidr(subnet0).subnets():
                for subnet2 in ip_cidr(subnet1).subnets():
                    for subnet3 in ip_cidr(subnet2).subnets():
                        for subnet4 in ip_cidr(subnet3).subnets():
                            for subnet5 in ip_cidr(subnet4).subnets():
                                for subnet6 in ip_cidr(subnet5).subnets():
                                    yield subnet6


def nmap_host_discovery(subnet) -> str:
    nmap = sp.run(
        ''.join(['nmap -n -sn -T5 ', str(subnet)]), capture_output=True)
    return nmap.stdout.decode()


# ---------------------------------------------------------------------------__

if __name__ == '__main__':
    print('Program Start...')
    main()

    input('\n\nEnter to end: ')

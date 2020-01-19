# Illumio-Challenge
Firewall system to accept or reject packets based on specified rules.

## Execution
To execute the firewall run:
```
python illumio.py filepath_for_csv
```
This initializes a firewall with the rules provided in the specified csv file. 
Once Initialized follow instructions on screen to enter packet information to be checked. If the firewall contains a rule that matches the packet specs, the program will return True, else it will return False.

## Implementation and Performance
The main goal behind all the design decisions of this submission was to keep query time during runtime as small as possible which in turn increased Firewall initialization time. The Firewall class is implemented with a nested dictionary data member which stores the direction of rules and the protocol of packets as it's keys. The dictionary then extends to an array of 65535 interval trees. This was done to index IP addresses of the rules through its port numbers taking O(1) time to access port number. The AVL based self balancing interval tree stores ip address ranges in O(log(n)) time with n being the number of rules the firewall is initialized with. It also allows access in O(log(n)) time. The overall performance in worst case is thus O(65535 x log(n)) to initialize the Firewall with rules and a constant O(log(n)) time complexity to query rules to check if a packet must be allowed or not at runtime. The interval tree code was heavily inspired from https://stackoverflow.com/questions/18922461/augment-java-collection-to-get-interval-tree with a few changes to work for this particular application. The biggest performance drain obtained is in terms of space which has to store and maintain 65535 interval tree elements.

## Testing
The testing of the firewall was done for basic test cases including ones with port numbers encomnpassing the entire allowable range and the same with the ip addresses. Furthermore a test script was made for this purpose: illumiotest.py. To execute the test run:
```
python illumiotest.py
```
When run, this script creates a csv file withh randomly generated rules named TestRules.csv. It also creates a file named TestAccepptableRules.csv that contains randomly generated packets that would abide by the rules generated in TestRules.csv. The firewall is then checked against these rules and allowable packets to see if any packet that needs to be allowed is blocked.

## Future Work
Initially I was keen on implementing a sort of nested interval tree structure that would represent ports and ip addressess and thus do away with the need to create a static 65535 sized array just to index ports. However in the given time I wasn't able to air out some of the kinks that I encountered during its implemementation like overlapping port and ip address intervals, etc. Furthermore I also feel the need for more manual and automated testing to avoid errors due to unhandled packets that need to be blocked. 

## Team Preferences
1. Data Team
2. Platform Team
3. Policy Team

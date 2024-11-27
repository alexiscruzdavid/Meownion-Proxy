# The Meownion Proxy
A simple TOR Protocol Application made as part of the distributed systems graduate level course (CS512 at Duke)

"In implementing the MeowOnion Proxy, we believed that accessing a TOR network has been stigmatized as a frightening and conspicuous activity, and so we wanted to model our program after a kind, charming creature such as a cat"

# Design Doc

For a more in-depth analysis of the software, we have written a design document also attached to this repository.

## Installation

Download/fork/clone this repository branch. 

## Running the Proxy

You can start up an instance of the Meownion Proxy network by running 
`python3 start_tor.py`

This will start up 5 relays and a proxy instance to interact with the network and send messages between relays. The program will also start up a terminal GUI such as the one below 

![image](https://github.com/user-attachments/assets/af0d1556-74a1-4a59-9a73-5a7dce4258ca)

A message can then be sent once prompted as well as a destination port (corresponding to one of the relays on the network). As this process takes place, output will be shown in the terminal logging the events taking place and the transfer of the packet between each relay. The creation of the relay circuit will also be made apparent.

## Testing
Various unit tests, which both mock and utilize real resources are available under the tests file. To run use this command
in the main directory,

`pytest -v`

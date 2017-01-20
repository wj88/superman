# SUPERMAN - Security Using Pre-Existing Routing for Mobile Ad hoc Networks #


## What is this reposoritory for? ##

To provide some background context, it would be best to refer to [this research paper](http://ieeexplore.ieee.org/document/7809102/).

The papers abstract is as follows:

*The flexibility and mobility of Mobile Ad hoc Networks (MANETs) have made them increasing popular in a wide range of use cases. To protect these networks, security protocols have been developed to protect routing and application data. However, these protocols only protect routes or communication, not both. Both secure routing and communication security protocols must be implemented to provide full protection. The use of communication security protocols originally developed for wireline and WiFi networks can also place a heavy burden on the limited network resources of a MANET. To address these issues, a novel secure framework (SUPERMAN) is proposed. The framework is designed to allow existing network and routing protocols to perform their functions, whilst providing node authentication, access control, and communication security mechanisms. This paper presents a novel security framework for MANETs, SUPERMAN. Simulation results comparing SUPERMAN with IPsec, SAODV and SOLSR are provided to demonstrate the proposed frameworks suitability for wireless communication security.*

This solution consists of two parts:

* SUPERMAN Linux Kernel Module
* SUPERMAN Linux Daemon

### Kernel Module ###

The kernel module provides the network layer packet processing required by SUPERMAN.

```
--------------------------------------------------
                 Transport Layer
--------------------------------------------------
         |        Network Layer        ^
         v                             |
    LOCAL OUT                      LOCAL IN
         |                             ^
         v                             |
  ---------------                      |
  |   ROUTING	|                      |
  ---------------                      |
         |                      ---------------
         |<--------FORWARD<-----|   ROUTING   |
         |                      ---------------
         |                             ^
         v                             |
    POST ROUTING                  PRE ROUTING
         |                             ^
         v                             |
--------------------------------------------------
                 Data Link Layer
--------------------------------------------------
```

As packets pass through local in and local out, SUPERMAN applies end-to-end encryption/decryption to the packet to secure it's contents. As packets pass through Post Routing and Pre Routing, SUPERMAN applies point-to-point HMAC tagging and verification.

In addition, the kernel module provides packet generation for the specialist SUPERMAN packet types and injects them into the appropriate parts of the network stack.

When loaded, the kernel module provides a number of proc filesystem entries.

```

cat /proc/superman/version          # Display the SUPERMAN kernel version
cat /proc/superman/security_table   # Summary of the data stored in the security table
cat /proc/superman/interfaces_table # Summary of the interfaces and whether SUPERMAN is applied
cat /proc/superman/queue_info       # Summary of the state of the packet queue_info
```

The SUPERMAN kernel module is unable to operate on it's own as it uses [public key certificates](https://en.wikipedia.org/wiki/Public_key_certificate) and [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) which, by way of it's implementation, requiring userland libraries and, in turn, the SUPERMAN daemon.

### Daemon ###

The daemon provides support to the kernel module as well as an element of control over how the kernel module works.

The daemon communicates with the kernel module through a generic netlink interface an is therefore dependant on libnl-genl-3.0. It also requires a minimum OpenSSL version of 1.0.2d (this is when the ability to include a Diffie-Hellman key share within the certificate was introduced).

## Trying SUPERMAN ##

You have a number of options for trying out SUPERMAN. You can use the test environment provided which emulates nodes using virtual machines to demonstrate how SUPERMAN works. Alternatively you can install SUPERMAN to a set of real devices in a live environment to try it out.

The following guide has been tested and works with (although may not be limited to) the following:

* Ubuntu x64 16.04 - desktop prefered although tested with server using SSH X tunnelling (ssh -X).
* Kernel version 4.4.
* Running as a regular user who has sudo permissions.

Clone the repository and change into the repos directory:

````

git clone https://bitbucket.org/wj88/superman.git
cd superman
````

### Trying SUPERMAN in the test environment ###

You can try out SUPERMAN in a emulated test environment.

Change into the test directory:

```

cd test
```

The source tree makes using of Makefiles to support the build process. There are a number of options which can be used but we're going to focus on the building the test environment and running a simulation. To make life easier, you can get up and running with a single command.

```

make sim
```

This command will:


* ensure the prerequists are installed
* compile the kernel-module
* compile the daemon
* build a custom root filesystem, based on the current ubuntu system, including
    * deboostraps a new root filesystem
    * downloads prerequiste apt packages required and extracts them
    * incorperates the kernel-module and daemon
    * incorperates supporting scripts
    * builds an image of the filesystem
* runs the test, including
    * sets up a network bridge interface for the nodes to talk over
    * configures a tap for each node
    * execute a qemu instance for each node, using the current systems kernel and custom root filesystem, in non-persistant mode (filesystem changes will be lost)
    * saves pcap files for each node under /tmp

Layer 3 IP network communication between each qemu instance is secured using SUPERMAN.

To try it you can run the following from node 3:

```

ping -c 5 10.0.0.2
```

The ping will send packets from node 3 and return to node 2. The actual data communicated is secured.

To verify the communication between nodes was in fact secured, the pcap files for each node are captured and stored under /tmp. To take a look at the contents of these files, it is recommended that you use the provided wireshark dissector which can interpret the contents of SUPERMAN packets. To do this, from the host computer (not a qemu instance):

````

./run-wireshark
````

From withim wireshark, open up the individual nodes pcap files from /tmp.


### Trying SUPERMAN in a live environment ###

Please note, SUPERMAN is not designed to be used in an environment where nodes are Internet connected. There is not yet any kind of gateway support to securely allow packets out of the MANET. The best way to experiment with this is using a set of single board computers, such as the Raspberry Pi. In addition, you will need to use a MANET routing protocol or configure static routes in advance which are set at system boot - this guide does not help with this.

### Installing ###

An APT package can be generated from the git repo. This package itself contains the source code for SUPERMAN and builds the binaries when installed on the nodes. This keeps the package architecture independant and, as the kernel-module needs to be build per kernel anyway, seems to make sense.

To build the APT package:

````

./build-aptpkg.sh
````

The output is superman_1.0_all.deb which can then be copied over to the target nodes and install using:

````

sudo dpkg -i superman_1.0_all.deb
````

If this fails with a message about the package depending on something that isn't installed, you can fix it with:

````

sudo apt-get -fy install
```` 

### Setting up security ###

SUPERMAN requires a CA to be used for the generation of signed certificates. The CA does not need to be accessible when the system is running, just for certificate generation. The system used as the CA will need OpenSSL >= 1.0.2d to be able to produce certificates which use diffie-hellman keys.

To create a CA certificate (which only needs to be done once), typically with the CA's /etc/superman/ directory:

````

# Make sure the /etc/superman directory exists
mkdir -p /etc/superman

# Create a CA private root key
openssl genrsa -out /etc/superman/ca_privatekey.pem 2048

# Create a CA certificate
openssl req -x509 -new -nodes -subj "/C=UK/ST=London/L=Greenwich/O=University of Greenwich/OU=Faculty of Engineering and Science/CN=fes.gre.ac.uk" -key /etc/superman/ca_privatekey.pem -days 1024 -out /etc/superman/ca_certificate.pem

# Generate DH parameters (1024 bits long safe prime, generator 2):
openssl dhparam -out /etc/superman/dh_params.pem 1024

#
# Now copy the following to each node:
#	dh_params.pem
#	ca_certificate.pem
#
````

The dh_params.pem file must then be copied to each node to be used as part of the network. It is from these parameters that a node will generate their diffie-hellman public/private key pair. The ca_certificate.pem file is the CA's public certificate which is used to authenticate another nodes which they join the network.

Typically, these files will be copied to each nodes /etc/superman/ directory.

````

# Make sure the /etc/superman directory exists
mkdir -p /etc/superman

# Generate private key from the parameters (public key is derivable):
openssl genpkey -paramfile /etc/superman/dh_params.pem -out /etc/superman/node_dh_privatekey.pem

# Derive public key from the private key:
openssl pkey -in /etc/superman/node_dh_privatekey.pem -pubout -out /etc/superman/node_dh_publickey.pem

# Generate an RSA private key (public key is derivable):
openssl genrsa -out /etc/superman/node_rsa_privatekey.pem 1024

# Create a certificate request from the RSA key:
openssl req -new -key /etc/superman/node_rsa_privatekey.pem -out /etc/superman/node_rsa_certreq.csr

#
# Now copy the following to the CA to generate a certificate:
#	node_rsa_certreq.csr
#	node_dh_publickey.pem
#
````

The node_rsa_certreq.csr and node_dh_publickey.pem files must be copied to the CA. The CA will then use these to generate the node a signed certificate which can be verified by the other nodes with the network.

````

# With the certificate request and the DH public key, generate a DH certificate.
openssl x509 -req -in node_rsa_certreq.csr -CAkey /etc/superman/ca_privatekey.pem -CA /etc/superman/ca_certificate.pem -force_pubkey node_dh_publickey.pem -out node_certificate.pem -CAcreateserial

#
# Now copy the following back to the node:
#	node_certificate.pem
#
````

The node_certicicate.pem is the nodes personal certificate generated by the CA. It needs to be given back to the node so that it can be used by the node to identify itself when joining the network.

Typically, the node_certificate.pem file sits under the /etc/superman/ directory on the node.


### Settings ####

There is a settings file, /etc/superman/superman.conf, which is used to configure SUPERMAN. It is worth take a look to ensure it matches with where you placed your certificate files, etc.

````

nano /etc/superman/superman.conf
````

### Done ###

That's it. You're now ready to reboot your system and you should be up and running.

  
## Licence ##

Please note the license file (in the root of the source reposoritory name LICENCE) which is fairly open and flexible. The only condition is:

Any academic works (including but not limited to conference and journal papers) produced as a result of direct or indirect use of this software must cite the following publication:
[http://ieeexplore.ieee.org/document/7809102/](http://ieeexplore.ieee.org/document/7809102/)

```
Bibtex
@ARTICLE{
	7809102, 
	author={D. Hurley-Smith and J. Wetherall and A. Adekunle}, 
	journal={IEEE Transactions on Mobile Computing}, 
	title={SUPERMAN: Security Using Pre-Existing Routing for Mobile Ad hoc Networks}, 
	year={2017}, 
	volume={PP}, 
	number={99}, 
	pages={1-1}, 
	keywords={Ad hoc networks;Authentication;Mobile computing;Routing;Routing protocols;access control;authentication;communication system security;mobile ad hoc networks}, 
	doi={10.1109/TMC.2017.2649527}, 
	ISSN={1536-1233}, 
	month={},
}
```

## Who do I talk to? ##

Dr Jodie Wetherall <wj88@gre.ac.uk>

Faculty of Engineering Science, University of Greenwich
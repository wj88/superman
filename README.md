# SUPERMAN - Security Using Pre-Existing Routing for Mobile Ad hoc Networks #


## What is this reposoritory for? ##

To provide some background context, it would be best to refer to [this research paper](http://ieeexplore.ieee.org/xpls/abs_all.jsp?arnumber=7412128&tag=1).

In summary:

*The increasing autonomy of Mobile Ad Hoc Networks (MANETs) has enabled a great many large-scale unguided missions, such as agricultural planning, conservation and similar surveying tasks. Commercial and military institutions have expressed great interest in such ventures; raising the question of security as the application of such systems in potentially hostile environments becomes a desired function of such networks. Preventing theft, disruption or destruction of such MANETs through cyber-attacks has become a focus for many researchers as a result. Virtual Private Networks (VPNs) have been shown to enhance the security of Mobile Ad hoc Networks (MANETs), at a high cost in network resources during the setup of secure tunnels. VPNs do not normally support broadcast communication, reducing their effectiveness in high-traffic MANETs, which have many broadcast communication requirements. To support routing, broadcast updates and efficient MANET communication, a Virtual Closed Network (VCN) architecture is proposed. By supporting private, secure communication in unicast, multicast and broadcast modes, VCNs provide an efficient alternative to VPNs when securing MANETs. Comparative analysis of the set-up overheads of VCN and VPN approaches is provided between OpenVPN, IPsec, Virtual Private LAN Service (VPLS), and the proposed VCN solution: Security Using Pre-Existing Routing for MANETs (SUPERMAN).*

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
#!shell

cat /proc/superman/version          # Display the SUPERMAN kernel version
cat /proc/superman/security_table   # Summary of the data stored in the security table
cat /proc/superman/interfaces_table # Summary of the interfaces and whether SUPERMAN is applied
cat /proc/superman/queue_info       # Summary of the state of the packet queue_info
```

The SUPERMAN kernel module is unable to operate on it's own as it uses [public key certificates](https://en.wikipedia.org/wiki/Public_key_certificate) and [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) which, by way of it's implementation, requiring userland libraries and, in turn, the SUPERMAN daemon.

### Daemon ###

The daemon provides support to the kernel module as well as an element of control over how the kernel module works.

The daemon communicates with the kernel module through a generic netlink interface an is therefore dependant on libnl-genl-3.0. It also requires a minimum OpenSSL version of 1.0.2d (this is when the ability to include a Diffie-Hellman key share within the certificate was introduced).

Ideally, the daemon would be brought up at boot time, although for the purpose of testing, this is brought up in the test environment although with the init process.

The daemon can take several arguments although eventually most of the importants will be provided through configuration files:

````
#!shell

Usage: superman

-c, --ca_cert file      Location of the CA public certificate
-n, --node_cert file    Location of this nodes public certificate
-p, --dh_privkey file   Location of the DH private key file
-t, --test_cert         Location of a certificate to check against
-D, --Debug             Debug mode
-d, --daemon            Daemon mode, i.e. detach from the console
-V, --version           Show version
-?, --help              Show help
````

## How do I get set up? ##

You can try out SUPERMAN in a emulated test environment.

The following guide has been tested and works with (although may not be limited to) the following:

* Ubuntu x64 14.04 and 15.04 - desktop prefered although tested with server using SSH X tunnelling (ssh -X).
* Kernel version 4.2.
* Running as a regular user who has sudo permissions.

Clone the repository and change into the test directory:

```
#!shell

git clone git@bitbucket.org:wj88/superman.git
cd superman/test
```

The source tree makes using of Makefiles to support the build process. There are a number of options which can be used but we're going to focus on the building the test environment and running a simulation. To make life easier, you can get up and running with a single command.

```
#!shell

make sim
```

This command will:


* ensure the prerequists are installed
* compile the kernel-module
* compile the daemon
* clone and compile the correct version of OpenSSL
* build a custom initial ramdisk image based, modified from the current systems kernel, including
    * extracts the current systems initrd
    * downloads prerequiste apt packages required and extracts them
    * incorperates the kernel-module and daemon
    * incorperates supporting scripts
    * rebuilds the initrd
* runs the test, including
    * sets up a network bridge interface for the nodes to talk over
    * configures a tap for each node
    * execute a qemu instance for each node, using the current systems kernel and custom initrd
    * saves pcap files for each node under /tmp

Layer 3 IP network communication between each qemu instance is secured using SUPERMAN.

To try it you can run the following from node 3:

```
#!shell

ping -c 5 10.0.0.2
```

The ping will send packets from node 3 and return to node 2. The actual data communicated is secured. You can take a look at the pcap files to verify.
  
## Licence ##

Please note the license file (in the root of the source reposoritory name LICENCE) which is fairly open and flexible. The only condition is:

Any academic works (including but not limited to conference and journal papers) produced as a result of direct or indirect use of this software must cite the following publication:
[http://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=7412128](http://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=7412128)

```
Bibtex
@inproceedings{hurley2015virtual,
  title={Virtual closed networks: A secure approach to autonomous mobile ad hoc networks},
  author={Hurley-Smith, Darren and Wetherall, Jodie and Adekunle, Andrew},
  booktitle={2015 10th International Conference for Internet Technology and Secured Transactions (ICITST)},
  pages={391--398},
  year={2015},
  organization={IEEE}
}
```

## Who do I talk to? ##

Dr Jodie Wetherall <wj88@gre.ac.uk>

Faculty of Engineering Science, University of Greenwich
# Helper for use of rpcbind Based Protocols with firewalld

With the new major releases openSUSE Leap 15.0 and SUSE Linux Enterprise 15
the *SuSEfirewall2* default firewall is replaced by
[firewalld](https://www.firewalld.org/).

While most features of *SuSEfirewall2* have an equivalent in *firewalld* there
is one major feature missing: The support for rpcbind based protocols like
NFSv3 and ypserv/ypbind.

*rpcbind* (formerly *portmapper*) is a dynamic port assignment protocol.
*rpcbind* listens on the fixed port 111. Other services that are based on
*rpcbind* choose arbitrary free ports to listen on and register with *rpcbind*
using a program number to identify themselves. Remote hosts can now talk to
*rpcbind* on port 111 to find out the actual port that one of the *rpcbind*
based services listens on.

This dynamic approach is naturally difficult to cope with in firewall setups.
*SuSEfirewall2* included quite complex code to deal with this situation.
firewalld does not offer this at the moment. The recommended approach to fix
this is to assign static ports to the involved services.

This configuration is somewhat cumbersome to perform manually. The python
utility provided in this repository helps with interactively or
programmatically setting up static ports for the most important remaining
uses of *rpcbind*.

Please refer to the usage and help output provided by `firewall-rpc-helper -h`
for more detail information on how to use it.

## License

This program is published under the GNU GPL version 2.0. See the accompanied
`LICENSE` file.

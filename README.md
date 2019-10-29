# netzfeger
netzfeger - automated DNS blacklisting with unbound 



Netzfeger focuses mainly on Debian driven Linux distributions using apt and dpkg internally, but is easily adjustable/extendable to be used on other distributions, too.
Therefor see the already available Options, which are still commented right now.


Purpose is installing unbound as a local DNSSEC validating DNS cache with the posibility to maintain blacklists of suspicious sites.

Local in this case can the local machine itelf or a local DNS server on the internal network.

Netzfeger allows you to maintain a blacklist and whitelist.
It also takes care of backups and restore of those.

The task to install a local server on the internal network is quite easy and automated.
For clients on the network netzfeger can be used to change the configs to take this DNS server for upstream requests.

A Apache webserver is taking care of requests on the blacklist.
Cronjobs can be installed to keep the blackist up to date.


Futher documentation soon to come...


Please report any errors!


Tested with Ubuntu (server and destop) 18.04 and 19.04 so far.



<<HELP text here>>






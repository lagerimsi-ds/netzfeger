#!/bin/bash

#
#
##
#####  NETZFEGER - SCRIPT   # # # 
##
#
#    - Install an DNSSEC validating local caching DNS server with unbound using TLS 
#      with the ability to work as a forwarder to the local network.
#    - Blacklisting of trackers and malware sites with help of blocklists and blocklist collections.
#    - Easy whitelist maintaining.
#    - Easy backup and recovery of all edited configuration files.
#
#    
#    Copyright (C) 2019  Dominik Steinberger
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
#



### setting variables by distribution
#
# system=ubuntu
#
# function test_distribution {
# 	system = $(lsb_release -is)
# }
#
# if [ "$system" = "ubuntu" || "$system" = "debian" || "$system" = "neon" ]
# then
#	variable_x=ubuntu_specific_setting
#	init_unbound_restart_command=systemctl restart unbound
#	...more variables here...
# elif [ "$system" = "fedora" ]
# then
#	variable_x=fedora_specific_setting
#	...more variables here...
# elif [ "$system" = "arch" ]
# then
#       variable_x=arch_specific_setting 
#	...more variables here...
#
# elif [ "$system" = "devuan" ]
# then
#       variable_x=arch_specific_setting 
#	init_unbound_restart_command=/etc/init.d/unbound restart
#	...more variables here...
#
#
# ...more distributions here ...
#
#
# else
#	echo "No real operating system detectable."
# fi
#
#
# ATTENTION - HELP WANTED:
# Several more command-variables have to be set and exchanged in the script to be fully interchangeable for distriburions.
# Also some paths may have to go into variables and be exchanged in the functions (for example apache2 configuraton directories).
# For init system commands: search for "systemctl".
# For package names search for "install_preq".
# Help is very welcome!
#




####
# variables
####

source_dir=$(dirname "${BASH_SOURCE[0]}")

temp_dir=$source_dir/netzfeger-tmp


unbound_blacklist_tmp=$temp_dir/collect/blacklist_collect.txt
unbound_whitelist_tmp=$temp_dir/collect/whitelist_collect.txt
unbound_blacklist_whitelisted_tmp=$temp_dir/collect/blacklist_whitelisted_collect.txt

unbound_conf_dir=/etc/unbound/unbound.conf.d
unbound_etc_conf=/etc/unbound/unbound.conf
unbound_std_conf=$unbound_conf_dir/netzfeger_unbound.conf
unbound_forwarders_conf=$unbound_conf_dir/netzfeger_forwarders.conf
unbound_server_conf=$unbound_conf_dir/netzfeger_server.conf

unbound_blacklist=$unbound_conf_dir/netzfeger_blacklist.conf
unbound_whitelist=$unbound_conf_dir/netzfeger_whitelist




# for download of conf files related to this script
git_url=https://github.com/lagerimsi-ds/netzfeger
git_raw_url=https://raw.githubusercontent.com/lagerimsi-ds/netzfeger/master


# different by distribution/OS
cert_store=/etc/ssl/certs
ca_cert=ca-certificates.crt
#cert_path_for_sed="$cert_store\/$ca_cert"
www_document_root=/var/www
packet_search="dpkg -l"
installer="sudo apt-get -y install"
init_unbound_restart_command="sudo systemctl restart unbound"
init_unbound_reload_command="sudo systemctl reload unbound"


# regexp patterns
link_pattern="^(https?|ftps?)://([0-9a-z]+[0-9a-z-]*\.)*([0-9a-z]+[0-9a-z-]*)+\.([a-z]+)+/.*$" # http and ftp links with at least domain and tld, subdomains possible and path possible
url_pattern="^([0-9a-z]+[0-9a-z-]*\.)*([0-9a-z]+[0-9a-z-]*\.)+([a-z]+)+$" # tld = true, domain = true, subdomain and below = may  ... aka hostname!
url_pattern_grep="'^([0-9a-z]+[0-9a-z-]*\.)*([0-9a-z]+[0-9a-z-]*\.)+([a-z]+)+$'" # tld = true, domain = true, subdomain and below = may for grep
ipv4_pattern="(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])" #)[^127.*|10.*|192.168.*|172.16.*|0.0.0.0]'"  # IPv4 w/o localhost
ipv6_pattern="[[:xdigit:]]{0,4}:{?}[[:xdigit:]]{0,4}:{?}[[:xdigit:]]{0,4}:{?}[[:xdigit:]]{0,4}:{?}[[:xdigit:]]{0,4}:{?}[[:xdigit:]]{0,4}:[[:xdigit:]]{0,4}:[[:xdigit:]]{1,4}" # IPv6 w/o localhost
port_pattern="^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$" # ports (1-65535)

# gathering the network for access control as server and ip for blacklist
network=$(ip route show | grep "$(ip route show default | awk '{ print $5 }')" | grep -v default | awk '{ print $1 }')
ip=$(ip address show | grep "$(echo "$network" | sed -E 's/\..{1,4}\/.{2,3}$//g')" | awk '{ print $2 }' | sed 's/\/.*$//g')
unbound_version=$($packet_search unbound | tail -n1 | awk '{print $3}' | awk -F- '{print $1}')




###
# Prequisites
###


# test on non-interactive or interactive shell
interactive="no"

fd=0
if [[ -t "$fd" || -p /dev/stdin ]]
then
  interactive=yes
fi

prequisites=""



####
# functions
####

# Help function
function show_help  {
	echo -E "Usage: $0 [option]... [file/url]..."
	echo -E ""
# prepared for -S
#	echo -E "$0 [-dfghisSu --install-unbound-conf --activate-privacy-forwarders"
#	echo -E "	--create-unbound-blacklist --create-tmp-blacklist --install-webserver]"
	echo -E "$0 [-dfghisu --install-unbound-conf"
	echo -E "	--create-unbound-blacklist --create-tmp-blacklist --install-webserver"
	echo -E "   	--apply-whitelist]"
	echo -E "$0 [-aAw] [file/hostname]"
	echo -E "$0 [-b] [blacklist|whitelist|forwarders|server]"
	echo -E "$0 [-c] [hourly|daily|weekly|monthly]"
	echo -E "$0 [-D] [URL/hostname|IPv4|IPv6]"
	echo -E "$0 [-F --activate-client-conf] [IPv4/IPv6] [hostname] [optional: port]"
	echo -E "$0 [-r] [blacklist|whitelist|forwarders|server] [list]"
	echo -E "$0 [-t] [--set-cert-store --set-www-root] [directory]"
	echo -E "$0 [--download-blacklist] [file/http(s)-link/ftp(s)-link]"
	echo -E "$0 [--set-git-url --set-git-raw-url] [http(s)-link]"
	echo -E "$0 [ --set-packet-search-cmd --set-packet-install-cmd --set-unbound-restart-cmd"
	echo -E "		--set-unbound-reload-cmd] [string]"
	echo -E ""
	echo -E ""
	echo -E ""
	echo -E "-a  --add-whitelist [file/hostname]				add a hostname to the whitelist"
	echo -E "-A  --add-blacklist [file/hostname]				add a hostname to the blacklist"
	echo -E "-b  --backup	[blacklist|whitelist|forwarders|server]		backup blacklist,whitelist,"
	echo -E "								forwarder-config or server-config"
	echo -E "-c  --install-cronjobs	[hourly|daily|weekly|monthly]		install the necessary cronjobs; update"
	echo -E "								playlist in given period ('hourly' may"
	echo -E "								cause heavy load on the machine)"
	echo -E "-d  --remove-cron-jobs						remove the installed cronjobs"
	echo -E "-D  --remove-fowarders	[URL/hostname|IPv4|IPv6]		remove forwarders from config"
	echo -E "-f  --activate-privacy-forwarders				apply the standard privacy concerning" 
	echo -E "								DNS forwarders"
	echo -E "-F  --add-forwarders [IPv4/IPv6] [hostname] [optional: port]	add own forwarders"
	echo -E "-g  --git-clone							clone the git repository"
	echo -E "-h  --help							show this help"
	echo -E "-i  --install [file/http-link/ftp-link]			combination of: install unbound, apply"
	echo -E "								forwarders, download (optional: link)"
	echo -E "								and activate blacklists,install webserver" 
	echo -E "-r  --recover	[blacklist|whitelist|forwarders|server]	[list]	recover blacklist,whitelist,"
	echo -E "								forwarder-config or server-config"
	echo -E "								with 'list' file to recover can be choosen"
	echo -E "--install-unbound-conf						apply the standard configuration"
	echo -E "								for already installed unbound"
	echo -E "--download-blacklist	[file/http-link/ftp-link]		download the blacklists"
	echo -E "-s  --enable-server						allow DNS queries from the local network"
#	echo -E "-S  --enable-server-tls					register a trusted Certificate apply"
#	echo -E "								the options to configuration"
	echo -E "-t  --set-tempdir	[directory]				set the temporary directory to use" 
	echo -E "								will be created if needed"
	echo -E "-u  --update	[file/http-link/ftp-link			same as:"
	echo -E "								--download-blacklists (optional link)"
	echo -E "								--create-tmp-blacklist"
	echo -E "								--create-unbound-blacklist"
	echo -E "								takes the example blacklist collection"
	echo -E "								by default"
	echo -E "-w  --remove-from-whitelist [hostname]				remove an entry on the whitelist"
	echo -E "--activate-client-conf	[IPv4/IPv6] [hostname] [optional: port]	alter the config to use a local DNS server"
	echo -E "--create-unbound-blacklist					create the blacklist for unbound"
	echo -E "--create-tmp-blacklist						create a temporary blacklist only"
	echo -E "								containing hostnames"
	echo -E "--install-webserver						install the webserver to answer for"
	echo -E "								blacklisted domains"
	echo -E "--apply-whitelist						apply whitelist without adding content"
	echo -E "--set-git-url	 [http(s)-link]					set the git URL"
	echo -E "--set-git-raw-url	 [http(s)-link]				set the git raw-URL to fetch files from"
	echo -E "--set-cert-store						set path of the SSL certificate store"
	echo -E "--set-ca-cert							set the name of the certificate-bundle"
	echo -E "--set-www-root							set the webservers document root"
	echo -E "--set-packet-search-cmd						set search command of package system"
	echo -E "--set-packet-install-cmd					set package system install command"
	echo -E "--set-unbound-restart-cmd					set init sytsem restart commmand for unbound"
	echo -E "--set-unbound-reload-cmd					set init sytsem reload commmand for unbound"
	exit 1
}



function install_preq {

	# ---- nice try ;) (works without package-management ---
	# another approach to test for the availability of the wanted program/executable
	# test if program is intalled within a diretory given in $PATH
	# if [ -x $(IFS=:; for dir in "$PATH"; do find $dir -name $1; done) ]; then ...; else ...; fi

	# test if package is installed
	if $packet_search "$1"
	then
		echo "OK: Prequisite $1 installed." 
		
	else		
		echo -E "$1 is missing. Installing now."
		if ! $installer "$1" 
		then
			echo "Installation failed. Aborting."
			exit 1
		fi
	fi
}



function reload_unbound {
	# reload unbound 


	echo -e "\n"
	echo -E "=============================================================================="
	echo -E "Reloading Unbound. All changes will be applied to production without shutting down the server."
	echo -E "=============================================================================="
	echo -e "\n"
	$init_unbound_reload_command
	#sleep 10
}



function restart_unbound {
        # restart unbound 
	# for server option
		
	echo -e "\n"
	echo -E "=============================================================================="
        echo -E "Restarting Unbound. Server will be not reachable for a moment."
	echo -E "=============================================================================="
	echo -e "\n"
        $init_unbound_restart_command
	#sleep 10
}



function create_tempdir {
	# create temporary directory

	if [ ! -d "$temp_dir"/collect ]
	then 
		echo -E "Create temporary directories in $temp_dir."
		mkdir -p "$temp_dir/collect"
		mkdir "$temp_dir/confs"
		mkdir "$temp_dir/collection-files"
	else
		echo -E "Temporary directory $temp_dir exists. OK."
	fi
}



function remove_tempdir {
	# asking to remove the temporary directory and its files
	remove="y"

	if [ $interactive = "yes" ]
	then
		echo -e "\n"
		echo -E "=============================================================================="
		read -p "Do you want to remove the teporary directory and all its files? [n]" remove
		echo -E "=============================================================================="
	fi
	
	if [ "$remove" = "y" ]
	then
		if [ -d "$temp_dir" ]
		then
			rm -R "$temp_dir"
		else
			echo -E "$temp_dir does not exist."
		fi
	else #remove must be "n" or smth. else
		echo -E "=============================================================================="
		echo -E "Kept $temp_dir. Please remove by hand if not needed anymore."
	fi
}



function install_webserver {
	# checking if apache2 is installed and install it if necessary

	install_preq apache2

	if [ ! -d "$www_document_root"/netzfeger ]
	then
		sudo mkdir -p "$www_document_root"/netzfeger
	fi

	if [ ! -f "$source_dir"/confs/netzfeger_apache.html ]
	then
		current_dir="$temp_dir"

		wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_apache.html
		wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_apache_vhost.conf
		wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_stop.png
		
	else

		current_dir=$source_dir

	fi
	sudo cp "$current_dir"/confs/netzfeger_apache.html "$www_document_root"/netzfeger/index.html
	sudo cp "$current_dir"/confs/netzfeger_stop.png "$www_document_root"/netzfeger/netzfeger_stop.png
     	sudo cp "$current_dir"/confs/netzfeger_apache_vhost.conf /etc/apache2/sites-available/
	sudo a2enmod ssl
	sudo a2dissite 000-default
	sudo a2ensite netzfeger_apache_vhost
	sudo systemctl restart apache2

	if sudo ufw status | grep "Status: active"
	then
		echo -e "\n"
		echo -E "=============================================================================="
		echo -E "Firewall is activated."
		echo -E "If used as local server you should open port 80 and 443."
		echo -E "Use these commands or similiar:"
		echo -E "ufw allow proto tcp from 192.168.0.0/24 to any port 80 "
		echo -E "ufw allow proto tcp from 192.168.0.0/24 to any port 443 "
		echo -E "=============================================================================="
		echo -e "\n"
	fi
}



function install_unbound {
	
	# installing unbound enabled to use DNSSEC and upstream encryption
	# also taking care to alter a standard ubuntu system to work with it right away

	# checking if unbound is installed and getting version
	packet=unbound

	if  ! $packet_search "$packet"
	then
		echo "$packet is not installed! Installing now."
		
		if $installer "$packet" unbound-host 
		then 
			sleep 10
			echo "127.0.0.1 $HOSTNAME" | sudo tee -a /etc/hosts
			unbound_version=$($packet_search "$packet" | tail -n1 | awk '{print $3}' | awk -F- '{print $1}')
			alter_unbound_conf_std
	  
			if [ "$interactive" = "yes" ]
			then
				# Prompt for install applet.
				echo -e "\n"
				echo -E "=============================================================================="
				read -p "If you want to install an applet for the graphical desktop to check the functionality of DNSSEC? y/n [n]" dnssectrigger
				echo -E "=============================================================================="
	
				if [ "$dnssectrigger" = "y" ]
				then 
				$installer dnssec_trigger
				fi
			fi
			
			echo -e "\n"
			echo -E "=============================================================================="
			echo -E "=============================================================================="
			echo "To make the script work unbound has been installed and standard configuration was applied."
			echo "Please call the script with the same options again."
			echo -E "=============================================================================="
			echo -E "=============================================================================="
			echo -e "\n"
	  
		else 
			echo "Installation failed. Aborting."
	                exit 1
		fi
	else
		unbound_version=$($packet_search "$packet" | tail -n1 | awk '{print $3}' | awk -F- '{print $1}')
		echo -e "\n"
		echo -E "=============================================================================="
		echo -E "=============================================================================="
		echo -E "$packet is already installed."
		echo -E "You might want to alter its config and upstream servers."
		echo -E "Edit the configs found within $unbound_conf_dir or adapt the ones found within the git repository in the 'conf' directory, then use '-c' or '--tls-unbound-conf' to apply them." 
		echo -E "Add upstream DNS servers taking care of privacy. Use '-f' or '--activate-privacy-forwarders'"
		echo -E "Using your unbound installation as DNS server offering TLS encryptet services for other participants on your network. Use '-s' or '--enable-server'"
		echo -E "=============================================================================="
		echo -E "=============================================================================="
		echo -e "\n"
	fi
}



function backup {
	# backup if file exists
	# takes one  argument: 
	#	1: file to back up
	# The backup file will be in the same directory with an ending showing the exact backup-time
	# example:  "/etc/unbound/unbound.conf.d/blacklist.conf_backup-2019-08-04T16:03:59+09:00"
	#
	# purpose: backing up the active blacklist, whitelist or one of the created configs

	if [ -f "$1" ]
	then
		sudo cp "$1" "$1_backup-$(date -Iseconds)"
		echo -e "\n"
		echo -E "=============================================================================="
		echo -E "$1 is backed up to file: $1_backup-$(date -Iseconds)"
		echo -E "=============================================================================="
		echo -e "\n"
	else
		echo -e "\n"
		echo -E "$1 not found."
		echo -E "No file to backup."
		echo -e "\n"
	fi
}



function backup_list {
	# backup blacklist, whitelist, forwarders and server configuration
        # takes one of the selfspeaking parameters and uses them for the backup function.

	for par in "${backup_lists[@]}"
	do

	        if [ "$par" = "blacklist" ]
	        then
	                backup "$unbound_blacklist"
	        
	        elif [ "$par" = "whitelist" ]
	        then
	                backup "$unbound_whitelist"
	                backup "$unbound_blacklist"
			echo -e "\n"
	                echo "For consistency also the blacklist was backed up."
			echo -e "\n"
	
	        elif [ "$par" = "forwarders" ]
	        then
	                backup "$unbound_forwarders_conf"
	
	        elif [ "$par" = "server" ]
	        then
	                backup "$unbound_server_conf"

	        else
			echo -e "\n"
			echo -E "=============================================================================="
	                echo "backup takes four parameters:"
	                echo -e "blacklist, whitelist, forwarders, server\n"
	                echo "Take into account that with the whitelist also the blacklist will be backed up."
			echo -E "=============================================================================="
			echo -e "\n"
	        fi
	done
}



function recover {
	# recover action for reuse in recover_list()
	# takes two parameters set there
	
	recover_file=$(basename $1)
	backupfile="$(find "$unbound_conf_dir"/ -type f -name ""$recover_file"_backup-*" | sort | tail -n1)"
	backupfile_list=($(find "$unbound_conf_dir"/ -type f -name ""$recover_file"_backup-*" | sort -r))

	if [ "$2" = "list" ]
	then
		for fileindex in "${!backupfile_list[@]}"; do 
			printf "%s\t%s\n" "$fileindex" "${backupfile_list[$fileindex]}"
		done

		echo -e "\n"
		echo -E "=============================================================================="
		read -p "Which file do you want to recover? Enter the file number: [0]" number
                echo -E "=============================================================================="
		
		if ! [ ${#number} -gt 0 ]
		then
			number=0
		fi

		backupfile=${backupfile_list[$number]}
	fi		


	if [ -f "$backupfile" ]
        then
                sudo mv -f "$1" "$1".err
                sudo cp "$backupfile" "$1"
		echo -e "\n"
		echo -E "=============================================================================="
		echo -E "Recovered $1 from file $backupfile."
                echo -E "The unwanted $1 was moved to $1.err. Any previous $1.err was overwritten."
		echo -E "=============================================================================="
		echo -e "\n"

	else
		echo -e "\n"
                echo "No file to recover."
		echo -e "\n"
	fi
}



function recover_list {
	# recover backed up lists
	# takes one of the selfspeaking parameters and uses them for the recover function.

	for par in "${recover_lists[@]}"
	do
		for index in "${!recover_lists[@]}"
		do
		   	if [[ "${recover_lists[$index]}" = "$par" ]]
			then
				par_follow=${recover_lists[($index+1)]}
			fi       
		done

		if [ "$par" = "blacklist" ]
		then
			if [ "$par_follow" = "list" ]
			then
				recover "$unbound_blacklist" list
			else
				recover "$unbound_blacklist"
			fi
			reload_unbound

		
		elif [ "$par" = "whitelist" ]
		then
			if [ "$par_follow" = "list" ]
			then
				recover "$unbound_whitelist" list
				recover "$unbound_blacklist" list
			else
				recover "$unbound_whitelist"
				recover "$unbound_blacklist" 
		
				echo -e "\n"
				echo "For consistency also the blacklist was recovered."
				echo -e "\n"
			fi
			reload_unbound
	
		elif [ "$par" = "forwarders" ]
		then
			if [ "$par_follow" = "list" ]
			then
				recover "$unbound_forwarders_conf" list
			else
				recover "$unbound_forwarders_conf"
			fi
			reload_unbound
	
		elif [ "$par" = "server" ]
		then
			if [ "$par_follow" = "list" ]
			then
				recover "$unbound_server_conf" list
			else
				recover "$unbound_server_conf"
			fi
			restart_unbound
		elif [ "$par" = "list" ]
		then
			continue
		else
			echo -e "\n"
			echo -E "=============================================================================="
			echo "recover takes four parameters:"
			echo "blacklist, whitelist, forwarders, server"
			echo -E "=============================================================================="
			echo -e "\n"
		fi
	done
}



function git_clone {
	
	install_preq git
		

	if [ "$interactive" = "yes" ]
	then
		echo -e "\n"
		echo -E "=============================================================================="
		read -p "Please set the path to clone the git repository to. [$source_dir]" dir
		echo -E "=============================================================================="
		echo -e "\n"
	fi

	if [ ! -d "$dir" ] 
	then 
		dir=$source_dir
	fi

	git clone $git_url "$dir"
	cd "$dir"
	source_dir=$dir
}



function dl_blacklists {
	# 1. create a temporary ditrectory
	# 2. add lists to download arrays - differ between collection files and single list URLS
	# 3. download the single lists to tempdir
	# 3. download the collection lists and their blocklists to tempdir (standard: firebog.net-blocklist collection)
	#  --> speedup by parallel
 	
	install_preq parallel
	create_tempdir	

	if [[ ! "${dl_list[0]}" =~ $link_pattern ]] || [ ! -f "${dl_list[0]}" ]
	then
		dl_list=("$(cat "$source_dir"/confs/blocklist-collection_example.txt)")
		echo -e "\n"
		echo -E "=============================================================================="
		echo -E "The example blocklist-collection (from firebog.net) was used!"
		echo -E "If possible take part or donate to the blocklist authors for their great work."
		echo -E "Be aware that some of thereby included blocklists may not be free for commercial use."
		echo -E "=============================================================================="
		echo -e "\n"
		sleep 10
	fi


	# fill arrays with entries
	for par in "${dl_list[@]}"
	do
			
		if [ -f "$par" ]
		then
			dl_array_file+=("$par")
	
		elif [[ "$par" =~ $link_pattern ]]
		then
			dl_array_links+=("$par")
		else
			
			echo -e "\n"
			echo -E "No file or URL specified."
			echo -e "\n"
		fi
	done
		
	# download files and list files given as links to temp_dir
	echo -e "\n"
	echo -E "Downloading blocklists to $temp_dir/"
	echo -e "\n"
	printf '%s\n' "${dl_array_links[@]}" | parallel wget --retry-on-host-error -P "$temp_dir"/ {}
	# copy files given to temp_dir
	for file in "${dl_array_file[@]}"
	do
		cp "$file" "$temp_dir"/
	done

	
	# parsing files for links which have still to be downloaded 
	# move them after extraction of those links to be out of the way for further blocklist-creation
	still_to_dl=()
	files=($(find "$temp_dir" -maxdepth 1 -type f))

	for file in "${files[@]}"
	do
		if grep -m 1 -o -E "$link_pattern" "$file"
		then 
			still_to_dl+=("$(grep -o -E "$link_pattern" "$file")")
			mv "$file" "$temp_dir"/collection-files
		fi
	done

	# download lists found in files
	printf '%s\n' "${still_to_dl[@]}" | parallel wget --retry-on-host-error -P "$temp_dir"/ {} 

}




function create_temp_blacklist() {
	# 1. remove existing blocklist and create a new one
	# 2. parsing every blocklist in the tempdir in parallel and add the entries to the tempcollection
	# 2.1 filter function -- grep URLs (no "single hostnames W/o domain) - keep care they are NOT IPs nor IPv6 hex digits -- add the URLS to collection

	install_preq parallel
	create_tempdir

	if [ -f "$unbound_blacklist_tmp" ]
	then
		rm "$unbound_blacklist_tmp"
		touch "$unbound_blacklist_tmp"
		echo -e "\n"
		echo "Old temporary blacklist was removed..."
		echo -e "\n"
	fi

	echo -e "\n"
	echo "Creating new temporary blacklist..."
	echo -e "\n"

	parallel grep -o -E "$url_pattern_grep" ::: "$(find "$temp_dir" -maxdepth 1 -type f)" | sort -r | uniq | tee -a "$unbound_blacklist_tmp" 

}



function create_unbound_blacklist {
	# backup old list
	# create new unbound blacklist; filter out two-part-TLDs beginning with a dot and format list to unbound-format
	

	if [ -f "$unbound_blacklist_tmp" ]
	then
		backup "$unbound_blacklist"
	
		echo -e "\n"
		echo "Finalizing unbound blacklist from file $unbound_blacklist_tmp."
		echo -e "\n"

		echo "server:" | sudo tee  "$unbound_blacklist"


		awk '{ print "local-zone: \"" $1 "\" redirect\nlocal-data: \"" $1 " A 127.0.0.1\"" }' "$unbound_blacklist_tmp" | sort -r | uniq | sudo tee -a "$unbound_blacklist"
	
		apply_whitelist
		
		reload_unbound
	else
		echo -e "\n"
		echo "No blacklist created. Did you create download and create a temporary blacklist?"
		echo -e "\n"
		show_help
	fi
}



function apply_whitelist {
	# remove the entries in the whitelist from the blocklist aka apply an existing whitelist to the blocklist
	# used by add_unbound_whitelist() and 
	
	if [ -f "$unbound_whitelist" ]
	then
		create_tempdir
		if [ -f "$unbound_blacklist_whitelisted_tmp" ]
		then
			rm -f "$unbound_blacklist_whitelisted_tmp"
		fi

		touch "$unbound_blacklist_whitelisted_tmp"

		parallel grep -v -f "$unbound_whitelist" ::: "$unbound_blacklist" | sort -r | uniq | tee -a "$unbound_blacklist_whitelisted_tmp"
		backup "$unbound_blacklist"
		sudo cp "$unbound_blacklist_whitelisted_tmp" "$unbound_blacklist"
	else
		echo -e "\n"
		echo -E "No whitelist to apply."
		echo -e "\n"
	fi

	reload_unbound
}




function add_unbound_whitelist {
	# adds new entries to an existing whitelist or creates one with the ones given
	# handles single entries or whole files
	# 
	install_preq parallel
	create_tempdir

	if [ -f "$unbound_whitelist" ]
	then
		# backup old whitelist
		backup "$unbound_whitelist"
		
		# initialize new temporary whitelist
		if [ -f "$unbound_whitelist_tmp" ]
		then
			rm -f "$unbound_whitelist_tmp"
			touch "$unbound_whitelist_tmp"
		fi		

               	for arg in "${whitelist_entry[@]}"
                do
                        if [ -f "$arg" ]
                        then
                                cat "$arg" | sed '/^$/d' | sort | uniq | tee -a "$unbound_whitelist_tmp"

                        elif [[ "$arg" =~ $url_pattern ]]
			then
                                echo -E "$arg"  | tee -a "$unbound_whitelist_tmp"
			else
				echo -e "\n"
				echo "No file or URL specified."
				echo -e "\n"
				exit 1
                        fi
                done
		
		# find entries which are not already in the whitelist and add them
		if [ -s "$unbound_whitelist" ]
		then
			if grep -xvq -f "$unbound_whitelist_tmp" "$unbound_whitelist"
			then
				parallel grep -xv -f "$unbound_whitelist" ::: "$unbound_whitelist_tmp" | sort | uniq | sudo tee -a "$unbound_whitelist"
				apply_whitelist
			else
				recover "$unbound_whitelist"

				echo -E "Recovered whitelist because the entries where already present."
			fi
		else
			sudo rm -f "$unbound_whitelist"
			sudo touch "$unbound_whitelist"

			if [ -s "$unbound_whitelist_tmp" ]
			then
				cat "$unbound_whitelist_tmp" | sort | uniq | sudo tee -a "$unbound_whitelist"
				apply_whitelist
			fi
		fi
		

	else
		# initialize new whitelist
		sudo touch "$unbound_whitelist"
		touch "$unbound_whitelist_tmp"

		for arg in "${whitelist_entry[@]}"
        	do
                	if [ -f "$arg" ]
                	then
                	        cat "$arg" | sed '/^$/d'  | sort | uniq | sudo tee -a "$unbound_whitelist_tmp"

                        elif [[ "$arg" =~ $url_pattern ]]
			then
                	        echo -E "$arg"  | sudo tee -a "$unbound_whitelist_tmp"
			else
				echo -e "\n"
				echo "No file or URL specified."
				echo -e "\n"
				exit 1
                	fi
			
        	done
		cat "$unbound_whitelist_tmp" | sort | uniq | sudo tee -a "$unbound_whitelist"
		apply_whitelist
		
	fi
}



function remove_from_whitelist {
	backup "$unbound_whitelist"
	
	for arg in "${remove_wl[@]}"
	do
		if grep "$arg" "$unbound_whitelist"
		then
			sudo sed -i "/^$arg$/d" "$unbound_whitelist"
		
		else
			recover "$unbound_whitelist"
			echo -E "Recovered, because entry was not found in $unbound_whitelist."
		fi
	done
}



function add_unbound_blacklist {
	# add an entry to the blacklist
	# initialize new temporary whitelist
	if [ -f "$unbound_blacklist_tmp" ]
	then

		backup "$unbound_blacklist_tmp"
		touch "$unbound_blacklist_tmp"
	else
		create_tempdir
		touch "$unbound_blacklist_tmp"
	fi

	already_in_whitelist=()

        for arg in "${blacklist_entry[@]}"
        do
        	if grep "$arg" "$unbound_whitelist"
		then
			already_in_whitelist+=("$arg")

		elif [ -f "$arg" ]
        	then
                	 cat "$arg" |  grep -x -E "$url_pattern_grep" | sort | uniq | tee -a "$unbound_blacklist_tmp"

                elif [[ "$arg" =~ $url_pattern ]]
		then
                	echo -E "$arg" | tee -a "$unbound_blacklist_tmp"
		else
			echo -e "\n"
			echo "No file or URL specified."
			echo -e "\n"
			exit 1
                fi
	done
	# apply to blacklist
	if [ -s "$unbound_blacklist_tmp" ]
	then
		create_unbound_blacklist
	fi
	
	if [ ${#already_in_whitelist[@]} -gt 0 ]
	then
		echo -e "\n"
		echo -E "=============================================================================="
		echo -E "These enties are in the whitelist: ${already_in_whitelist[@]}"
		echo -E "Use netzfeger.sh -w <entry> to remove them in front of adding to the blacklist."
		echo -E "=============================================================================="
		echo -e "\n"
	fi
}



function alter_unbound_conf_std {

	if [ -s "$unbound_conf_dir"/root.hints ]
	then 
		return
	fi

	create_tempdir

	if  grep -q "include \"$unbound_conf_dir/\*\.conf\"" "$unbound_etc_conf"
	then
		echo -E "include \"$unbound_conf_dir/*.conf\"" | sudo tee -a "$unbound_etc_conf"
	fi

	# remove old resolv.conf
	if [ -h /etc/resolv.conf ]  || [  -f /etc/resolv.conf ]
	then
		sudo cp /etc/resolv.conf /etc/resolv.conf.network-manager
		sudo rm /etc/resolv.conf
		sudo touch /etc/resolv.conf
		echo "nameserver 127.0.0.1" | sudo tee -a /etc/resolv.conf
	fi
	
	# download root hint file
	while [ ! -s "$unbound_conf_dir"/root.hints ]
	do
		sudo wget --retry-on-host-error -S -N https://www.internic.net/domain/named.cache -O "$unbound_conf_dir"/root.hints
	done

	# install daemon dependencies
	if [ ! -d /etc/systemd/system/unbound.service.d ]
	then
		sudo mkdir -p /etc/systemd/system/unbound.service.d
	fi

	sudo cp "$source_dir"/confs/netzfeger_systemd_unbound_service.conf /etc/systemd/system/unbound.service.d/netzfeger_systemd_unbound_service.conf



	if [ "$(systemd --version | grep -E "^systemd [[:digit:]]*$" | awk '{ print $2 }')" -gt 239 ]
	then
		sudo systemctl enable systemd-time-wait-sync.service
		if [ ! -d /etc/systemd/system/unbound.service.d ]
		then
			sudo mkdir -p /etc/systemd/system/unbound.service.d
		fi
		echo "After=systemd-time-wait-sync.service" | sudo tee -a /etc/systemd/system/unbound.service.d/netzfeger_systemd_unbound_service.conf
#		echo "Requires=systemd-time-wait-sync.service" | sudo tee -a /etc/systemd/system/unbound.service.d/netzfeger_systemd_unbound_service.conf

		# User Info
		echo -e "\n"
		echo "Using systemd-time-wait-sync.service introduced in version 239 of systemd to start up after time is synced over the network - not just service started up."
		echo -e "\n"
	else
		cat << 'EOF'


===============================================================================
===============================================================================
Try to upgrade to a version equal or higher to '239' of systemd (shipped for example with ubuntu 19.04 and above) . This will enable you to make use of the "systemd-time-wait-sync.service".

Without this service the "time-sync.target" which unbound depends on gives tells to be started but the time is not synced yet. So the check of the anchor file will fail.
This can be solved by restarting unvound after booting into the desktop/final stage. 
The script will take care of this problem by installing a "restart service" which restarts unbound on every boot.

===============================================================================
===============================================================================


EOF
		if [ "$interactiv" = "yes" ]
		then
			echo -e "\n"
			echo -E "=============================================================================="
			read -p  "Do you want to install a service that restarts unbound after all other services have been started on every boot? [y/n]" service_install
			echo -E "=============================================================================="
			echo -e "\n"

			if [ "$service_install" = y ]
			then
				
				sudo mkdir /root/bin/
				sudo touch /root/bin/restart_service_for_unbound.sh
				sudo chmod +x /root/bin/restart_service_for_unbound.sh
				echo -E "systemctl restart unbound" | sudo tee -a /root/bin/restart_service_for_unbound.sh
				sudo cp "$source_dir"/confs/restart_service_for_unbound.service /lib/systemd/system/
				sudo systemctl enable restart_service_for_unbound.service
			fi
		else
		
				sudo mkdir /root/bin/
				sudo touch /root/bin/restart_service_for_unbound.sh
				sudo chmod +x /root/bin/restart_service_for_unbound.sh
				echo -E "systemctl restart unbound" | sudo tee -a /root/bin/restart_service_for_unbound.sh
				sudo cp "$source_dir"/confs/restart_service_for_unbound.service /lib/systemd/system/
				sudo systemctl enable restart_service_for_unbound.service
		fi

				

	fi			


	# get logical cores of CPU to set later as threads
	threads="$(lscpu -pCPU | tail -n+5 | wc -l)"


	# apply new config - download in front if needed

	if [ ! -f "$source_dir"/confs/netzfeger_unbound.conf ]
	then
		current_dir="$temp_dir"/confs

		wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_unbound.conf
		wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_unbound_before_v1.9.0.conf
	else
		current_dir="$source_dir"/confs
	fi


	
	# test version and copy appropriate config file
	if [ "$unbound_version" = "$(echo -e "$unbound_version\n1.9.0" | sort -V | tail -n1)" ]
	then

		#sed -i "s/num-threads\:.*$/num-threads\: $threads/g" "$current_dir"/netzfeger_unbound.conf  
		#sed -i "s/tls-cert-bundle=.*$/tls-cert-bundle\: $cert_path_for_sed/g" "$current_dir"/netzfeger_unbound.conf 
		#sed -i '/num-threads\:.*$/d' "$current_dir"/netzfeger_unbound.conf
		echo -e  "\tnum-threads: $threads" | tee -a "$current_dir"/netzfeger_unbound.conf
		sed -i '/tls-cert-bundle=.*$/d' "$current_dir"/netzfeger_unbound.conf
		echo -e  "\ttls-cert-bundle: $cert_store/$ca_cert" | tee -a "$current_dir"/netzfeger_unbound.conf

		sudo cp "$current_dir"/netzfeger_unbound.conf "$unbound_std_conf"

	else
		#sed -i '/num-threads\:.*$/d' "$current_dir"/netzfeger_unbound_before_v1.9.0.conf
                echo -e "\tnum-threads: $threads" | tee -a "$current_dir"/netzfeger_unbound_before_v1.9.0.conf

		#sed -i "s/num-threads\:.*$/num-threads\: $threads/g" "$current_dir"/netzfeger_unbound_before_v1.9.0.conf
		sudo cp "$current_dir"/netzfeger_unbound_before_v1.9.0.conf "$unbound_std_conf"
	fi

	# apply the privacy forwarder because they are capable of DNSsec requests and encrypted connections which are forced in the new unbound.conf
	alter_unbound_conf_privacy_forwarders

	# disable the systemd-resolver
	sudo systemctl disable systemd-resolved
	# stopping the sysemd-resolver
	sudo systemctl stop systemd-resolved
	
	# enable unbound daemon on startup
	sudo systemctl enable unbound
	
	#restart_unbound

}



function alter_unbound_conf_privacy_forwarders {
	# install privacy respecting forwarders 
	# testing on include statement in main config file
	# testing version in front to set the appropriate variables
	create_tempdir
	
	if grep -q "include \"$unbound_conf_dir/\*\.conf\"" "$unbound_etc_conf"
	then
		echo -E "include \"$unbound_conf_dir/*.conf\"" | sudo tee -a "$unbound_etc_conf"
	fi

	if [ ! -f "$source_dir"/confs/netzfeger_forwarders.conf ]
	then
		current_dir="$temp_dir"/confs

	        wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_forwarders.conf
	        wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_forwarders_before_v1.9.0.conf

	else
		current_dir="$source_dir"/confs
	
	fi
        
        
	#test version and copy appropriate config file

	if [ "$unbound_version" = "$(echo -e "$unbound_version\n1.9.0" | sort -V | tail -n1)" ]
	then
	
                sudo cp "$current_dir"/netzfeger_forwarders.conf "$unbound_forwarders_conf"

        else

                sudo cp "$current_dir"/netzfeger_forwarders_before_v1.9.0.conf "$unbound_forwarders_conf"
        fi

	# Support message for privacy respecting DNS forwarders applied by default
	# Info about round-robin DNS queries in unbound (-> privacy +)
	cat << 'EOF'	

===============================================================================
===============================================================================

These pivacy respecting and DNSsec capable forwarders have been set by default:"
===============================================================================

# SecureDNS.eu DNS Server
146.185.167.43@853#dot.securedns.eu
d2a03:b0c0:0:1010::e9a:3001@853#dot.securedns.eu
"    
# Dismail.de DNS Server
u0.241.218.68@853#fdns1.dismail.de
ua02:c205:3001:4558::1@853#fdns1.dismail.de
"    
# Digitalcourage e.V.
46.182.19.48@853#dns2.digitalcourage.de
2a02:2970:1002::18@853#dns2.digitalcourage.de


In respect of the work and good will to offer these services for public use
visit their websites and donate if possible to keep the services running!


Info:
By default unbound uses them randomly and thereby improves your privacy.
Why?
Even if the providers are logging you DNS requests they only gather info about
some sites you visit.

The more DNS providers added the higher the privacy.
You can change the providers by using the --add-forwarders option.
" 

===============================================================================
===============================================================================


EOF
}



#function alter_unbound_conf_sever_tls {
#	# backup existing netzfeger_server.conf
#	# install netzfeger_server.conf in the config directory with the appropriate settings
#	# mention to open ports in the local firewall if exists and active
#
#
#	# backup
#	if [ -f $unbound_server_conf ]
#	then
#		backup_list server
#	fi
#
#
### preparation for automated TLS certificate generation using acmetools
##
## acmetools commands here
##
### providers are for example letsencrypt.org
##
##
##
#
#
#	if grep -q "include \"$unbound_conf_dir/\*\.conf\"" "$unbound_etc_conf" 
#	then
#		echo -E "include \"$unbound_conf_dir/*.conf\"" | sudo tee -a "$unbound_etc_conf"
#	fi
#
#	# depending on version set the local server as forwarder -- if version is the last in sort order i.e. greater or equal 1.9.0
#        if [ "$unbound_version" = "$(echo -e "$unbound_version\n1.9.0" | sort -V | tail -n1)" ]
#        then
#		# set private-cert-key and pem
#	        sudo sed -i "s/tls-service-key=.*$/tls-service-key: $cert_store/$(hostname -f).key/g" "$unbound_server_conf"
#	        sudo sed -i "s/tls-service-pem=.*$/tls-service-pem: $cert_store/$(hostname -f).pem/g" "$unbound_server_conf"
#		
#		
#        else
#		# set private-cert-key and pem
#	        sudo sed -i "s/ssl-service-key=.*$/ssl-service-key: $cert_store/$(hostname -f).key/g" "$unbound_server_conf"
#	        sudo sed -i "s/ssl-service-pem=.*$/ssl-service-pem: $cert_store/$(hostname -f).pem/g" "$unbound_server_conf"
#         
#         fi
#
#
#
#	echo -E "The server is now capable to solve requests securd by TLS."
# 
#}



function alter_unbound_conf_server {
	# opening the server for local net use
	# backup config in front

	if [ -f $unbound_server_conf ]
	then
		backup "$unbound_server_conf"
	else	

	        if [ ! -f "$source_dir"/confs/netzfeger_conf.conf ]
	        then
	                create_tempdir
			current_dir=$temp_dir/confs
	
	               	wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_server.conf
	               	wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_server_before__v1.9.0.conf

		else
			current_dir="$source_dir"/confs

		fi
	fi
	
	# depending on version set the local server as forwarder -- if version is the last in sort order i.e. greater or equal 1.9.0
        if [ "$unbound_version" = "$(echo -e "$unbound_version\n1.9.0" | sort -V | tail -n1)" ]
        then
		if [ -f "$current_dir"/netzfeger_server.conf ]
		then 
			sudo mv "$current_dir"/netzfeger_server.conf "$unbound_server_conf"
		fi

	        # set cert-bundle to validate upstream servers
	        sudo sed -i "s/access-control=.*$/access-control: $network allow/g" "$unbound_server_conf"
	
        else
		if [ -f "$current_dir"/netzfeger_server_before__v1.9.0.conf ]
		then 
			sudo mv "$current_dir"/netzfeger_server_before__v1.9.0.conf "$unbound_server_conf"
		fi

	        sudo sed -i "s/access-control=.*$/access-control: $network allow/g" "$unbound_server_conf"
		
        fi

	backup "$unbound_blacklist"
	sudo sed -i "s/127.0.0.1/$ip/g" $unbound_blacklist

	if sudo ufw status | grep "Status: active"
	then
		echo -e "\n"
		echo -E "=============================================================================="
		echo -E "Firewall is activated."
		echo -E "As using unbound as a local server now you should open port 53."
		echo -E "Use these commands or similiar:"
		echo -E "ufw allow proto tcp from 192.168.0.0/24 to any port 53 "
		echo -E "=============================================================================="
		echo -e "\n"
	fi
}



function add_unbound_conf_forwarders {

	backup "$unbound_forwarders_conf"
#own local DNS serve
	# add 'edited' string in first line of forwarders.conf - if it is not already altered to a local server
	if ! grep -q "# netzfeger - edited" "$unbound_forwarders_conf"
	then
		sudo sed -i '1i# netzfeger - edited' "$unbound_forwarders_conf"
	fi

	# optional port argument - set to default port if not set
	if [ ${#forwarders[2]} -gt 0 ]
	then
		port="${forwarders[2]}"
	else
		port=853
	fi


	# depending on version set the local server as forwarder - test: version greater or equal 1.9.0 (last in sort)
	if [ "$unbound_version" = "$(echo -e "$unbound_version\n1.9.0" | sort -V | tail -n1)" ]
        then
		echo -e "\t#own local DNS server\n\tforward-address: ${forwarders[0]}@$port#${forwarders[1]}" | sudo tee -a "$unbound_forwarders_conf"

	else
		echo -e "\t#own local DNS server\n\tforward-address: ${forwarders[0]}@$port#${forwarders[1]}" | sudo tee -a "$unbound_forwarders_conf"

	fi
}



function delete_unbound_conf_forwarders {
	for par in "${forwarders_remove[@]}"
	do
		# test if file or single server given
		if grep "$par" "$unbound_forwarders_conf"
		then 
			sudo sed -i "/^.*$par.*$/d" "$unbound_forwarders_conf"

			if [[ $(tail -n1 "$unbound_forwarders_conf") =~ ^[[:space:]]*#own[[:space:]]{1}local[[:space:]]{1}DNS[[:space:]]{1}server.*$ ]]
			then
				sudo sed -i '$d' "$unbound_forwarders_conf"
			fi

		else
			echo -e "\n"
			echo -E "=============================================================================="
			echo -E "The forwarder was not found in $unbound_forwarders_conf."
			echo -E "=============================================================================="
			echo -e "\n"
		fi
	done
}



function install_cron_jobs {
	# install a cronjobs for updating the blacklists by set update intervall and random time
	# install root anchor updates at a weekly basis - random time

	case "$cron_intervall" in
		
		hourly)
			cron_update_intervall=hourly
			;;

		daily)
			cron_update_intervall=daily
			;;

		weekly)
			cron_update_intervall=weekly
			;;

		monthly)
			cron_update_intervall=monthly
			;;

		*)
			echo -e "\n"
			echo -E "Default set: weekly"
			echo -e "\n"
			cron_update_intervall=weekly # daily, weekly, monthly, (hourly - rather useless)
	esac

	# set path to script
	if [ -f "$source_dir"/confs/netzfeger_cron_anchor ]
	then
		current_dir=$source_dir
		if [ "$source_dir" = "." ]
		then 
			current_dir=$(pwd)
		fi
	else
		current_dir=$(pwd)
		wget --retry-on-host-error -P "$current_dir"/ $git_raw_url/confs/netzfeger_cron_anchor
	fi
	
	
	# install cronjob
	echo -E "/usr/bin/bash $current_dir/netzfeger.sh --update" | sudo tee -a /etc/cron.$cron_update_intervall/netzfeger_cron_blacklist_update

	# fetch anchor weekly - to not miss updates
	sudo cp "$current_dir"/confs/netzfeger_cron_anchor /etc/cron.weekly/netzfeger_cron_anchor	

	echo -e "\n"
	echo -E "=============================================================================="
	echo -E "Cronjobs have been installed."
	echo -E "The blacklist is kept up to date on a $cron_update_intervall basis."
	echo -E "The anchor file will be updated weekly."
	echo -E "=============================================================================="
	echo -e "\n"

}



function remove_cron_jobs {
	# remove the cronjob

	cron_jobs=($(find /etc/cron.* -type f -name "netzfeger*"))
	
	for job in "${cron_jobs[@]}"
	do
		sudo rm "$job"
	done

}	



function activate_client_conf {

	# set the local upstream-server, remove the force of upstream-tls
	backup "$unbound_forwarders_conf"
	sed -i '/^.*tls-upstream: yes.*$/d' "$unbound_std_conf"
	sed -i '/^.*ssl-upstream: yes.*$/d' "$unbound_std_conf"
	
	sed -i '3,$d' "$unbound_forwarders_conf"
	
	add_unbound_conf_forwarders
}
	

####
### Start getopt code ###
####

if [[ $# -eq 0 ]]
then 
	show_help
fi


while [[ $# -gt 0 ]]
do
	case "$1" in
        	-a|--add-whitelist)
			whitelist_entry=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				whitelist_entry+=("$2")
				shift
			done
			add_unbound_whitelist
			shift		        
	        	;;

        	-A|--add-blacklist)
			blacklist_entry=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				blacklist_entry+=("$2")
				shift
			done
			echo -E "$blacklist_entry"
			add_unbound_blacklist
			shift		        
	        	;;

		-b|--backup) 
			backup_lists=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				backup_lists+=("$2")
				shift
			done
			backup_list
        		shift
		        ;;
		-c|--install-cronjobs)
			cron_intervall="$2"
			install_cron_jobs
			shift 2
			;;

		-d|--remove-cron-jobs)
			remove_cron_jobs
			shift
			;;

	 	--install-unbound-conf)
			alter_unbound_conf_std
			shift
			;;

	 	--download-blacklist)
			dl_list=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				if [[ "$2" =~ $link_pattern ]] || [ -f "$2" ]
				then
					dl_list+=("$2")

				else
					echo -e "\n"
					echo -E "=============================================================================="
					echo -E "No link to a file or URL to some list or list file given: $2"
					echo -E "=============================================================================="
					echo -e "\n"
					break
				fi
				shift
			done
			dl_blacklists
			shift
			;;

	 	-f|--activate-privacy-forwarders)
			alter_unbound_conf_privacy_forwarders
			shift
			;;

                -F|--add-forwarders)
			forwarders=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do	
				if [[ "$2" =~ $ipv4_pattern || "$2" =~ $ipv6_pattern ]]	&& [[ "$3" =~ $url_pattern ]] && [[ "$4" =~ $port_pattern ]]
				then 
					forwarders+=("$2" "$3" "$4")
					shift 3

				elif [[ "$2" =~ $ipv4_pattern || "$2" =~ $ipv6_pattern ]] && [[ "$3" =~ $url_pattern ]]
				then
					forwarders+=("$2" "$3")
					shift 2

				else					
					echo -e "\n"
					echo -E "=============================================================================="
					echo -E "Usage: '[IPv4 or IPv6] [hostname] [port (optional)]'"
					echo -E "Several addresses and servers can be added by calling this option again."
					echo -E "Or specify a file with one server per line in this format:"
					echo -E "[IPv4 or IPv6] [hostname] [port (optional)]"
					echo -E "Example: '192.168.1.15 local-dnssec-server 853'"
					echo -E "=============================================================================="
					echo -e "\n"
				fi

			done

                        add_unbound_conf_forwarders
                        shift
                        ;;

		-D|--remove-forwarders)
			forwarders_remove=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				if [[ "$2" =~ $url_pattern || "$2" =~ $ipv4_pattern || "$2" =~ $ipv6_pattern ]]
				then
					forwarders_remove+=("$2")
					shift
				else
				
					echo -e "\n"
					echo -E "=============================================================================="
					echo -E "No URL or IPv4 or IPv6 given!"
					echo -E "=============================================================================="
					echo -e "\n"
				fi
			done
			delete_unbound_conf_forwarders
			shift
			;;

		-g|--git-clone)
			git_clone
			shift
			;;

	 	-h|--help)
			show_help
			shift
			;;

	 	-i|--install)
			dl_list=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				if [[ "$2" =~ $link_pattern ]] || [ -f "$2" ]
				then
					dl_list+=("$2")

				else
					echo -e "\n"
					echo -E "=============================================================================="
					echo -E "No link to a file or URL to some list or list file given: $2"
					echo -E "=============================================================================="
					echo -e "\n"
					break
				fi
				shift
			done
			git_clone
			install_unbound
			sleep 15
			install_webserver
			dl_blacklists 
			sleep 15
                        create_temp_blacklist
                        create_unbound_blacklist
			shift
			;;

	 	-r|--recover)
			recover_lists=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				if [ "$3" = "list" ]
				then
					recover_lists+=("$2" "$3")
					shift 2
				else
					recover_lists+=("$2")
					shift
				fi
			done
			recover_list
			shift
			;;

	 	-s|--enable-server)
			alter_unbound_conf_sever
			install_cronjob
			shift
			;;

#	 	-S|--enable-server-tls)
#			install_unbound
#			install_webserver
#			alter_unbound_conf_sever_tls
#			alter_blacklist_ip
#			shift
#			;;

	 	-t|--set-tempdir)
			if [ -d "$2" ]
                        then
                                temp_dir="$2"
                        else
				echo -E "No path for temp directory given!"
			fi
			shift 2
			;;

		-w|--remove-from-whitelist)
			remove_wl=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				remove_wl+=("$2")
				shift
			done
			remove_from_whitelist
			shift 
			;;

		--avtivate-client-conf)
			forwarders=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do	
				if [[ "$2" =~ $ipv4_pattern || "$2" =~ $ipv6_pattern ]]	&& [[ "$3" =~ $url_pattern ]] && [[ "$4" =~ $port_pattern ]]
				then 
					forwarders+=("$2" "$3" "$4")
					shift 3

				elif [[ "$2" =~ $ipv4_pattern || "$2" =~ $ipv6_pattern ]] && [[ "$3" =~ $url_pattern ]]
				then
					forwarders+=("$2" "$3")
					shift 2

				else					
					echo -e "\n"
					echo -E "=============================================================================="
					echo -E "Usage: '[IPv4 or IPv6] [hostname] [port (optional)]'"
					echo -E "Several addresses and servers can be added by calling this option again."
					echo -E "Or specify a file with one server per line in this format:"
					echo -E "[IPv4 or IPv6] [hostname] [port (optional)]"
					echo -E "Example: '192.168.1.15 local-dnssec-server 853'"
					echo -E "=============================================================================="
					echo -e "\n"
				fi

			done
			activate_client_conf
			shift
			;;

	 	--create-unbound-blacklist)
			create_unbound_blacklist
			shift
			;;

	 	--create-tmp-blacklist)
			create_temp_blacklist
			shift
			;;

	 	-u|--update)
			dl_list=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				if [[ "$2" =~ $link_pattern ]] || [ -f "$2" ]
				then
					dl_list+=("$2")

				else
					echo -e "\n"
					echo -E "=============================================================================="
					echo -E "No link to a file or URL to some list or list file given: $2"
					echo -E "=============================================================================="
					echo -e "\n"
					break
				fi
				shift
			done
			dl_blacklists
			create_temp_blacklist
			create_unbound_blacklist
			shift
			;;

		--install-webserver)
			install_webserver
			shift
			;;

		--apply-whitelist)
			apply_whitelist
			shift
			;;

		--set-git-url)
			if  [[ "$2" =~ $link_pattern ]]
			then
				git_url="$2"
			else
				echo -e "\n"
				echo -E "No git-URL given!"
				echo -e "\n"
				exit 1
			fi
			shift 2
			;;

		--set-git-raw-url)
			if [[ "$2" =~ $link_pattern ]]
			then
				git_raw_url="$2"
			else
				echo -e "\n"
				echo -E "No git-raw-URL given!"
				echo -e "\n"
				exit 1
			fi
			shift 2
			;;
 
		--set-cert-store)
			if [ -d "$2" ]

			then
				cert_store="$2"
			else
				echo -e "\n"
				echo -E "No path to cert store given!"
				echo -e "\n"
				exit 1
			fi
			shift 2
			;;
	
		--set-ca-cert)
			if [ -f "$2" ]
			then 
				ca_cert="$2"
			else
				echo -e "\n"
				echo -E "No correct ca-filename given!"
				echo -e "\n"
				exit 1
			fi
			shift 2
			;;

		--set-document-root)
			if [ -d "$2" ]
			then
				www_document_root="$2"
			else
				echo -e "\n"
				echo -E "No correct path for document root given!"
				echo -e "\n"
				exit 1
			fi
			shift 2
			;;

		--set-packet-search-cmd)
			cmd=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				cmd+=("$2")
				shift
			done

			if [ "$interactive" = yes ]
			then
				echo -e "\n"
				echo -E "=============================================================================="
				read -p "Is the given command correct - please check again! ${cmd[*]} [n]" answer
				echo -E "=============================================================================="
				if [ "$answer" = "y" ]
				then
					packet_search="${cmd[*]}"
				else
					echo -e "\n"
					echo -E "Give the correct command and try again."
					echo -e "\n"
					exit 1
				fi
			else
				packet_search="${cmd[*]}"
			fi
			shift 
			;;

		--set-packet-install-cmd)
			cmd=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				cmd+=("$2")
				shift
			done

			if [ "$interactive" = yes ]
			then
				echo -e "\n"
				echo -E "=============================================================================="
				read -p "Is the given command correct - please check again! ${cmd[*]} [n]" answer
				echo -E "=============================================================================="
				if [ "$answer" = "y" ]
				then
					installer="${cmd[*]}" 
				else
					echo -e "\n"
					echo -E "Give the correct command and try again."
					echo -e "\n"
					exit 1
				fi
			else
				installer="${cmd[*]}"
			fi
			shift
			;;

		--set-unbound-restart-cmd)
			cmd=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				cmd+=("$2")
				shift
			done

			if [ "$interactive" = yes ]
			then
				echo -e "\n"
				echo -E "=============================================================================="
				read -p "Is the given command correct - please check again! ${cmd[*]} [n]" answer
				echo -E "=============================================================================="
				if [ "$answer" = "y" ]
				then
					installer="${cmd[*]}" 
				else
					echo -e "\n"
					echo -E "Give the correct command and try again."
					echo -e "\n"
					exit 1
				fi
			else
				installer="${cmd[*]}"
			fi
			shift 
			;;

		--set-unbound-reload-cmd)
			cmd=()
			while ! [[ $2 =~ ^-.* ]] && [[ $# -gt 1 ]]
			do
				cmd+=("$2")
				shift
			done

			if [ "$interactive" = yes ]
			then
				echo -e "\n"
				echo -E "=============================================================================="
				read -p "Is the given command correct - please check again! ${cmd[*]} [n]" answer
				echo -E "=============================================================================="
				if [ "$answer" = "y" ]
				then
					installer="${cmd[*]}" 
				else
					echo -e "\n"
					echo -E "Give the correct command and try again."
					echo -e "\n"
					exit 1
				fi
			else
				installer="${cmd[*]}"
			fi
			shift 
			;;

		--)
			shift
			break
			;;

	        *)
			show_help
			exit 1
		        ;;
	esac
done

####
# finish
####

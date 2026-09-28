#!/bin/bash

UNAME_S=`uname -s`
PKG_MGR=
INSTALL_CMD=" -y install"

os_specific () {
	if [[ "$OSTYPE" == "linux-gnu" ]]; then
        # Linux

		local FN="${1}_linux"

	elif [[ "$OSTYPE" == "darwin"* ]]; then
		# macOS

		local FN="${1}_macos"

	else
		echo "System not supported"
		# Unknown
	fi

	$FN
}

ard () {
	ARD_CMD=$1

	# /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
	mvar=$(ps ax | grep -i ardagent | grep -c -v grep)
	if [ $mvar -eq 1 ]; then
		echo "ARD running"
	else
		echo "No ARD process found"
	fi


	# /System/Library/LaunchDaemons/com.apple.screensharing.plist
	# 
	mvar=`ps ax | grep -i screensharingd | grep -c -v grep`
	if [ $mvar -eq 1 ]; then
		echo "Screen sharing running"
	else
		echo "No Screen sharing daemon found"
	fi
	

	# sudo launchctl kill KILL system/com.apple.screensharing

	# https://apple.stackexchange.com/questions/278744/command-line-enable-remote-login-and-remote-management
	# https://support.apple.com/en-us/HT201710
	# sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist

	ARD_KICKSTART=/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart

	# https://wiki.mozilla.org/ReleaseEngineering/How_To/Access_Machines_via_VNC
	# $ARD_KICKSTART -configure -allowAccessFor -allUsers -privs -all
	#  -activate
	# sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on -users admin -privs -all -restart -agent -menu

	# VNC
	# $ARD_KICKSTART -configure -clientopts -setvnclegacy -vnclegacy yes

	# VNC password
	# $ARD_KICKSTART -configure -clientopts -setvncpw -vncpw supersecret

	# restart
	# $ARD_KICKSTART -restart -agent -console

	# listen only on local interface
	# sudo defaults write /Library/Preferences/com.apple.RemoteManagement.plist VNCOnlyLocalConnections -bool yes
	
	# In newer versions of macOS, screen sharing will automatically re-lock the screen when you disconnect if it was locked when you first connected. To change this behavior, use:
	# sudo defaults write /Library/Preferences/com.apple.RemoteManagement RestoreMachineState -bool NO

	# https://www.jamf.com/jamf-nation/discussions/1989/reporting-ard-status

	#!/bin/sh
	#mvar=$(ps ax | grep -c -i "[Aa]rdagent")
	#if [ $mvar -eq 1 ]; then
	#echo "<result>Running</result>"
	#else 
	#echo "<result>Not Running</result>"
	#fi

}

# https://feeding.cloud.geek.nz/posts/usual-server-setup/

init_linux () {
	sudo $PKG_MGR $INSTALL_CMD net-tools vim nano etckeeper git sudo curl

	# TODO: check for python, install ansible
}

# https://askubuntu.com/questions/47311/how-do-i-disable-my-system-from-going-to-sleep

initialize_insomnia_linux () {
	#	● sleep.target - Sleep
	#   Loaded: loaded (/lib/systemd/system/sleep.target; static; vendor preset: enabled)
	#   Active: inactive (dead)
	#   Docs: man:systemd.special(7)

	#	● sleep.target
	#   Loaded: masked (Reason: Unit sleep.target is masked.)
	#   Active: inactive (dead)

	sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

	# OR

	# gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout '0'
	# gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout '0'

	# dconf read /org/gnome/settings-daemon/plugins/power/lid-close-battery-action 'nothing'
	# dconf read /org/gnome/settings-daemon/plugins/power/lid-close-ac-action 'nothing'
	# dconf read /org/gnome/settings-daemon/plugins/power/idle-dim false

	# OR

	# sudo vi /etc/default/acpi-support # and then set SUSPEND_METHODS="none"
	# sudo /etc/init.d/acpid restart

}

initialize_insomnia_macos () {
	sudo systemsetup -setallowpowerbuttontosleepcomputer off
	sudo systemsetup -setrestartfreeze on
	sudo systemsetup -setrestartpowerfailure on
	sudo systemsetup -setcomputersleep off
	sudo systemsetup -setsleep off
}

initialize_insomnia () {
	os_specific initialize_insomnia
}

NewLocalAdminUser () {
	$USER_
	/usr/sbin/usermod -a -G sudo user
}

add_user_to_sudoers () {
	SUDO_USER=${1:-${USER}}
	/usr/sbin/usermod -a -G sudo $SUDO_USER
}

enable_firewall () {
	# debian
	apt install ufw
	ufw allow OpenSSH # ufw allow ssh
	ufw enable
	ufw status
	# centos
	# firewall-cmd --zone=public --permanent --add-service=ssh
	# firewall-cmd --reload

}

start_cert_share_server () {
    CERT_USERNAME="${1:-${USER}}"
    TEMP_DIRNAME="$(mktemp -d /tmp/certshare.XXXXXXXXX)"

    cp "$HOME/${CERT_USERNAME}.crt.pem" "$TEMP_DIRNAME/cert.pem"
    cp "$HOME/${CERT_USERNAME}.key.pub" "$TEMP_DIRNAME/key.pub"

    (
        cd "$TEMP_DIRNAME" || exit 1

        if [ "$STORE_PID" = "1" ]; then
            echo $$ > ./process.pid
        fi

        python3 -m http.server 8000
    )
}

# sudo update-alternatives --config editor

# zypper install -y curl # -y should be after install

enable_sshd_linux () {
	if ! sudo systemctl is-active ssh ; then
		if $PKG_MGR $INSTALL_CMD openssh-server ; then
			if ! sudo systemctl is-active ssh ; then
				if ! sudo systemctl is-enabled ssh ; then
					sudo systemctl enable ssh
				fi
				sudo systemctl start ssh
			fi
		fi
	fi
}

enable_sshd_macos () {
	SSHD_STATUS=$(sudo systemsetup -getremotelogin)
	sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
	
	# systemsetup -setremotelogin on # deprecated

	# by default ssh is allowed only for machine administrators
	# dseditgroup -o create -q com.apple.access_ssh
	# dseditgroup -o edit -a admin -t group com.apple.access_ssh
}

enable_sshd () {
	os_specific enable_sshd
}

new_client_auth_cert () {
	# Set the name of the local user that will have the key mapped to
	CERT_USERNAME=${1:-${USER}}
	TEMP_FILENAME=$(mktemp /tmp/winrm.XXXXXXXXX)

	cat > $TEMP_FILENAME << EOL
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req_client]
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$CERT_USERNAME@localhost
EOL

	export OPENSSL_CONF=$TEMP_FILENAME
	openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out $HOME/${CERT_USERNAME}.crt.pem -outform PEM -keyout $HOME/${CERT_USERNAME}.key.pem -subj "/CN=$CERT_USERNAME" -extensions v3_req_client
	unset OPENSSL_CONF # export -n OPENSSL_CONF
	rm $TEMP_FILENAME

	chmod 600 $HOME/${CERT_USERNAME}.key.pem

	ssh-keygen -f $HOME/${CERT_USERNAME}.key.pem -y > $HOME/${CERT_USERNAME}.key.pub
}

if [ "x$UNAME_S" == "xDarwin" ] ; then
	
	# ard status
	echo macOS

	# https://apple.stackexchange.com/questions/278744/command-line-enable-remote-login-and-remote-management

	# SSH Enable
	# sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist

elif [ "x$UNAME_S" == "xLinux" ] ; then

	# init_linux
	echo Linux

	[[ -x "/usr/bin/zypper" ]] && PKG_MGR="zypper" && PKG_INSTALL=" install -y"
	[[ -x "/usr/bin/dnf" ]]    && PKG_MGR="dnf"
	[[ -x "/usr/bin/yum" ]]    && PKG_MGR="yum"
	[[ -x "/usr/bin/apt" ]]    && PKG_MGR="apt"
	# packman ?

	echo $PKG_MGR

else

	echo "Unsupported OS: $UNAME_S"
	exit 1

fi

echo "Tools for controller machine:"
echo "new_client_auth_cert <username>"

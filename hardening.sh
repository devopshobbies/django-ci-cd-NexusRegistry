#!/bin/bash
# Time Variable Section --------------------------------------
HOUR=`date +%H`
WEEK=`date +%A`
MONTH=`date +%Y-%d`
DAY=`date +%Y-%m-%d`
NOW="$(date +"%Y-%m-%d_%H-%M-%S")"
# Variable Section -------------------------------------------
DOMAIN_NAME=devopshobbies.com
HostName=$DOMAIN_NAME
SSH_PORT=1242
BAC_DIR=/opt/backup/files_$NOW
# docker config destination
DOCKER_DEST=/etc/systemd/system/docker.service.d/
MIRROR_REGISTRY=https://docker.jamko.ir
#-------------------------------------------------------------

echo "Info: ------------------------------------"
echo -e "DNS Address:\n`cat /etc/resolv.conf`"
echo -e "Hostname: $HOSTNAME"
echo -e "OS Info:\n`lsb_release -a`"
echo -e "ssh port: $SSH_PORT"
echo "------------------------------------------"

# create directory backup ------------------------------------
if [ -d $BAC_DIR ] ; then
   echo "backup directory is exist"
else
   mkdir -p $BAC_DIR
fi   

# Preparing os ----------------------------------------------------
# Update OS
apt update && apt upgrade -y 

# Remove unuse package
apt remove -y snapd && apt purge -y snapd

# install tools
apt install -y wget git vim nano bash-completion curl htop iftop jq ncdu unzip net-tools dnsutils \
               atop sudo ntp fail2ban software-properties-common apache2-utils tcpdump telnet axel

# Host Configuration ------------------------------------------
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mHostname Configuration \e[0m"
hostnamectl set-hostname $HostName

# Timeout Config -----------------------------------------------
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mTimeout Setting \e[0m"
echo -e '#!/bin/bash\n### 300 seconds == 5 minutes ##\nTMOUT=300\nreadonly TMOUT\nexport TMOUT' > /etc/profile.d/timout-settings.sh
cat /etc/profile.d/timout-settings.sh

#config sysctl.conf: -----------------------------------------
cp /etc/sysctl.conf $BAC_DIR
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mSysctl Configuration \e[0m"
cat <<EOT >> /etc/sysctl.conf
# Decrease TIME_WAIT seconds
net.ipv4.tcp_fin_timeout = 30
 
# Recycle and Reuse TIME_WAIT sockets faster
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1

# Decrease ESTABLISHED seconds
net.netfilter.nf_conntrack_tcp_timeout_established=3600

# Maximum Number Of Open Files
fs.file-max = 500000

# 
vm.max_map_count=262144

net.ipv4.ip_nonlocal_bind = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1

#Kernel Hardening
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.sysrq = 0 
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

#New Kernel Hardening
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0

# Disable Ipv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.ipv4.conf.all.rp_filter=1
kernel.yama.ptrace_scope=1
EOT
echo "root soft nofile 65535" >  /etc/security/limits.conf
echo "root hard nofile 65535" >> /etc/security/limits.conf
echo "root soft nproc 65535" >> /etc/security/limits.conf
echo "root hard nproc 65535" >> /etc/security/limits.conf

echo "* soft nofile 2048" >  /etc/security/limits.conf
echo "* hard nofile 2048" >> /etc/security/limits.conf
echo "* soft nproc  2048" >> /etc/security/limits.conf
echo "* hard nproc  2048" >> /etc/security/limits.conf
modprobe br_netfilter

# sysctl config apply 
sysctl -p

#-------------------------------------------------------------
# postfix Service: disable, stop and mask
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mpostfix Service: disable, stop and mask \e[0m"
systemctl stop postfix
systemctl disable postfix
systemctl mask postfix

#-------------------------------------------------------------
# firewalld Service: disable, stop and mask
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mfirewalld Service: disable, stop and mask \e[0m"
systemctl stop firewalld
systemctl disable firewalld
systemctl mask firewalld

#-------------------------------------------------------------
# ufw Service: disable, stop and mask
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mufw Service: disable, stop and mask \e[0m"
systemctl stop ufw
systemctl disable ufw
systemctl mask ufw

# create ssh banner -------------------------------------------
cat <<EOT > /etc/issue.net
------------------------------------------------------------------------------
* WARNING.....                                                               *
* You are accessing a secured system and your actions will be logged along   *
* with identifying information. Disconnect immediately if you are not an     *
* authorized user of this system.                                            *
------------------------------------------------------------------------------
EOT

# sshd_config edit this parameters ------------------------------
cp /etc/ssh/sshd_config $BAC_DIR
cat <<EOT > /etc/ssh/sshd_config
Port $SSH_PORT
ListenAddress 0.0.0.0

# Logging
LogLevel VERBOSE

# Authentication:
#LoginGraceTime 2m
PermitRootLogin yes
#PermitRootLogin without-password
#StrictModes yes
MaxAuthTries 3
MaxSessions 2
#PubkeyAuthentication yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication yes
#PermitEmptyPasswords no

ChallengeResponseAuthentication no

# GSSAPI options
GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

UsePAM yes

AllowAgentForwarding no
AllowTcpForwarding no
#GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
TCPKeepAlive no
#UseLogin no
#PermitUserEnvironment no
Compression no
ClientAliveInterval 10
ClientAliveCountMax 10
UseDNS no

# no default banner path
Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

AllowUsers root 
AllowGroups root
EOT

#sshd config test
sshd -t

#ssh service: enable, restart and status
{
systemctl enable sshd.service 
systemctl restart sshd.service 
systemctl is-active --quiet sshd && echo -e "\e[1m \e[96m sshd service: \e[30;48;5;82m \e[5mRunning \e[0m" || echo -e "\e[1m \e[96m sshd service: \e[30;48;5;196m \e[5mNot Running \e[0m"
}

#Copy Public Key -------------------------------------------
#cat <<EOT >> /root/.ssh/authorized_keys
# AmirBahador
# ssh-rsa YOURSSH KEY
#EOT

# fail2ban config -----------------------------------------
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
# ssh config 
sed -i '/^\[sshd\]/a enabled = true' /etc/fail2ban/jail.local
sed -i 's/port    = ssh/port    = '$SSH_PORT'/g' /etc/fail2ban/jail.local
sed -i 's/port     = ssh/port    = '$SSH_PORT'/g' /etc/fail2ban/jail.local
# service restart and status service
{
systemctl enable fail2ban.service 
systemctl restart fail2ban.service
systemctl is-active --quiet fail2ban && echo -e "\e[1m \e[96m fail2ban service: \e[30;48;5;82m \e[5mRunning \e[0m" || echo -e "\e[1m \e[96m fail2ban service: \e[30;48;5;196m \e[5mNot Running \e[0m"
sleep 2
fail2ban-client status
}

# Iptables config ---------------------------------------------

DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent

cp /etc/iptables/rules.v4 $BAC_DIR
cat <<EOT > /etc/iptables/rules.v4 
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:CHECK_INPUT - [0:0]
:CHECK_OUTPUT - [0:0]
-A INPUT -j CHECK_INPUT
-A INPUT -j DROP
-A OUTPUT -j CHECK_OUTPUT
-A OUTPUT -j DROP
-A CHECK_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A CHECK_INPUT -i lo -j ACCEPT
-A CHECK_INPUT -i docker0 -j ACCEPT
-A CHECK_INPUT -p tcp -m tcp --dport $SSH_PORT -j ACCEPT
-A CHECK_INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A CHECK_INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A CHECK_INPUT -s 192.168.0.0/16 -j ACCEPT
-A CHECK_INPUT -s 172.17.0.0/16 -j ACCEPT
-A CHECK_INPUT -s DockerMe.ir -j ACCEPT -m comment --comment "The DockerMe Server Ip is Trusted"
-A CHECK_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A CHECK_OUTPUT -j ACCEPT
COMMIT
EOT
{
# load config iptables
iptables-restore /etc/iptables/rules.v4
iptables -nL
# restart fail2ban config
systemctl restart fail2ban
iptables -nL
}

# Install Docker --------------------------------------------------------------------
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mDocker Installation\e[0m" 
which docker || { curl -fsSL https://get.docker.com | bash; }
{
systemctl enable docker
systemctl restart docker
systemctl is-active --quiet docker && echo -e "\e[1m \e[96m docker service: \e[30;48;5;82m \e[5mRunning \e[0m" || echo -e "\e[1m \e[96m docker service: \e[30;48;5;196m \e[5mNot Running \e[0m"
}

# Configur Docker --------------------------------------------------------------------
if [ -d $DOCKER_DEST ] ; then
   echo "file exist"
else
   mkdir -p /etc/systemd/system/docker.service.d/
   touch /etc/systemd/system/docker.service.d/override.conf
fi   

cat <<EOT > /etc/systemd/system/docker.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --registry-mirror $MIRROR_REGISTRY --log-opt max-size=500m --log-opt max-file=5
EOT
cat /etc/systemd/system/docker.service.d/override.conf
{
systemctl daemon-reload
systemctl restart docker
systemctl is-active --quiet docker && echo -e "\e[1m \e[96m docker service: \e[30;48;5;82m \e[5mRunning \e[0m" || echo -e "\e[1m \e[96m docker service: \e[30;48;5;196m \e[5mNot Running \e[0m"
}

# Install docker-compose --------------------------------------------------------------------
echo -e " \e[30;48;5;56m \e[1m \e[38;5;15mdocker-compose Installation\e[0m" 
which docker-compose || { sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose; chmod +x /usr/local/bin/docker-compose; }

{
docker-compose --version
}

# change DNS ------------------------------------------------------------------------
cat /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 9.9.9.9" >> /etc/resolv.conf 
cat /etc/resolv.conf

# ------------------------------------------------------------------------------
#Docker Services WARNING
docker info | grep WARNING

#how to fix "WARNING: No swap limit support"
cat /etc/default/grub
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"/g' /etc/default/grub
cat /etc/default/grub
sudo update-grub

# create and edit rc.local -------------------------------------------------
echo '#!/bin/bash' >  /etc/rc.local
echo "iptables-restore /etc/iptables/rules.v4" >>  /etc/rc.local
echo "systemctl restart fail2ban.service" >>  /etc/rc.local
echo "systemctl restart docker.service" >>  /etc/rc.local
echo "exit 0" >>  /etc/rc.local
chmod +x /etc/rc.local
cat /etc/rc.local

# Remove all unused packages -------------------------------------------------------
apt autoremove -y

# timezone config ------------------------------------------------------------------
apt install -y ntp
timedatectl set-timezone Asia/Tehran
timedatectl | grep Time | cut -d ":" -f2 | cut -d " " -f2

{
   systemctl enable ntp
   systemctl restart ntp
   systemctl is-active --quiet ntp && echo -e "\e[1m \e[96m ntp service: \e[30;48;5;82m \e[5mRunning \e[0m" || echo -e "\e[1m \e[96m ntp service: \e[30;48;5;196m \e[5mNot Running \e[0m"
}

# bashrc configuration --------------------------------------------------------------
curl https://store.dockerme.ir/Software/bashrc -o /root/.bashrc

# lynis audit tools for Hardening check --------------------------------------------
if [ ! -d  "/opt/lynis" ]
then
   curl https://downloads.cisofy.com/lynis/lynis-3.0.6.tar.gz -o /opt/lynis.tar.gz
   cd /opt ; tar -xzf lynis.tar.gz ; rm -rf /opt/lynis.tar.gz
fi
cd /opt/lynis
./lynis audit system
#-----------------------------------------------------------------------------------

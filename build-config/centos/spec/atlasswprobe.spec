%define         installpath /usr/local/atlas

Name:           atlasswprobe
Summary:        RIPE Atlas probe software
Version:        4970
Release:        13%{?dist}
License:        RIPE NCC
Group:          Applications/Internet
Source1:        busybox-721e000967a2876646960f87b0a027a3b7e234f5.tar.gz
Source2:        scripts-8ac9a3ae1f872438290cd82244c33fa29026949a.tar.gz
Requires:       sudo %{?el6:daemontools} %{?el7:psmisc}
BuildRequires:  rpm %{?el7:systemd} openssl-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}

%description
This is the RIPE Atlas probe software. It's designed to run on CentOS Linux systems.

%prep
tar xf %{SOURCE1}
tar xf %{SOURCE2}
#rm -rf atlas-probe-scripts
#cp -r /home/atlas-dev/atlas-probe-scripts atlas-probe-scripts

%build
cd busybox/libevent-2.0.20-stable
./configure
make
cd ..
make

%install
cd busybox
make install
mkdir -p %{buildroot}%{installpath}/{bin,bin/arch/centos-sw-probe,bin/arch/linux,bb-13.3,etc,lib,state}
cp -r ./_install/* %{buildroot}%{installpath}/bb-13.3
cp ./libevent-2.0.20-stable/.libs/libevent-*so* %{buildroot}%{installpath}/lib
cp ./libevent-2.0.20-stable/.libs/libevent_openssl-*so* %{buildroot}%{installpath}/lib
cd ../atlas-probe-scripts
cp bin/{ATLAS,common-pre.sh,common.sh,reginit.sh} %{buildroot}%{installpath}/bin
cp bin/arch/centos-sw-probe/* %{buildroot}%{installpath}/bin/arch/centos-sw-probe
cp bin/arch/linux/* %{buildroot}%{installpath}/bin/arch/linux
cp atlas-config/state/* %{buildroot}%{installpath}/state
cp atlas-config/etc/* %{buildroot}%{installpath}/etc

%if 0%{?el7}
mkdir -p %{buildroot}%{_unitdir}
cat > %{buildroot}%{_unitdir}/atlas.service << EOF
[Unit]
Description=Atlas Probe
After=network-online.target syslog.target

[Service]
User=atlas
Group=atlas
Environment=HOME=/home/atlas
WorkingDirectory=/home/atlas
ExecStart=/usr/local/atlas/bin/ATLAS
Restart=always
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF
%endif

%if 0%{?el6}
mkdir -p %{buildroot}/etc/init
cat > %{buildroot}/etc/init/atlas.conf << EOF
start on stopped rc
stop on runlevel [016]
respawn
env HOME=/home/atlas
exec setuidgid atlas /usr/local/atlas/bin/ATLAS
post-stop script
    setuidgid atlas kill \$(cat /home/atlas/run/*pid.vol 2>/dev/null) 2>/dev/null || :
    setuidgid atlas rm -f /home/atlas/run/*pid.vol
end script
EOF
%endif

%clean
rm -rf %{buildroot}

%files
%{installpath}
%caps(cap_net_raw=ep) %{installpath}/bb-13.3/bin/busybox
%if 0%{?el7}
%{_unitdir}/atlas.service
%endif
%if 0%{?el6}
/etc/init/atlas.conf
%endif

%pre
%if 0%{?el7}
systemctl stop atlas &>/dev/null
killall -9 eooqd eperd perd telnetd 2>/dev/null || :
%endif
%if 0%{?el6}
stop atlas &>/dev/null
%endif
rm -fr /home/atlas/status /home/atlas/bin/reg_servers.sh

groupadd -g 10042 atlas 2>/dev/null
useradd -c atlas -d /home/atlas -g atlas -s /sbin/nologin -u 10042 atlas 2>/dev/null
exit 0

%post
exec >/tmp/atlasprobe.out 2>/tmp/atlasprobe.err
set -x

if [ ! -f /home/atlas/state/mode ]; then
    mkdir -p /home/atlas/state
    echo prod > /home/atlas/state/mode
fi
if [ ! -d /home/atlas/bin ]; then
    mkdir -p /home/atlas/bin
fi
echo 'DEVICE_NAME=centos-sw-probe' > /home/atlas/bin/config.sh
if [ ! -f /home/atlas/etc/probe_key ]; then
    ether=$(ip link | awk '/link\/ether/ { print $2; exit }')
    name=$(hostname -s)
    mkdir -p /home/atlas/etc
    ssh-keygen -t rsa -P '' -C $name -f /home/atlas/etc/probe_key
    chown -R atlas:atlas /home/atlas/etc
fi
chown -R atlas:atlas /home/atlas
chmod 755 /home/atlas

mkdir -p /home/atlas/crons/main
mkdir -p /home/atlas/crons/2
mkdir -p /home/atlas/crons/7
chown -R atlas:atlas /home/atlas/crons
mkdir -p /home/atlas/data/new
mkdir -p /home/atlas/data/oneoff
mkdir -p /home/atlas/data/out/ooq
mkdir -p /home/atlas/data/out/ooq10
chown -R atlas:atlas /home/atlas/data
chmod -R g+rwx /home/atlas/data
mkdir -p /home/atlas/run
chown atlas:atlas /home/atlas/run
%if 0%{?el7}
systemctl --now --quiet enable atlas
systemctl --now --quiet start atlas
%endif
%if 0%{?el6}
start atlas &>/dev/null
%endif
exit 0

%preun
if [ $1 -eq 0 ]; then
    # uninstall, otherwise upgrade
%if 0%{?el7}
    systemctl --now --quiet disable atlas
%endif
%if 0%{?el6}
    stop atlas &>/dev/null
%endif
fi
exit 0

%postun
if [ $1 -eq 0 ]; then
	%{?el7:%systemd_postun}
	rm -fr /home/atlas/etc/probe_key /home/atlas/status
fi

%changelog
* Thu Jul 6 2017 Anand Buddhdev <anandb@ripe.net>
- Updated the SPEC file to build for both CentOS 6 and 7

* Thu Mar 28 2013 Anand Buddhdev <anandb@ripe.net>
- Removed some redundant kill commands, because the upstart script takes care of that
- Added code to the post-stop hook in the upstart script to delete all PID files
* Wed Mar 27 2013 Anand Buddhdev <anandb@ripe.net>
- Embedded the upstart script into the spec file; switched from "su" to "setuidgid"
- Added a post-stop hook to the upstart script to kill all atlas child processes
- Fixed a typo in the "stop on" stanza in the upstart script
- Added shell code to the the pre-install and pre-uninstall hooks to kill atlas child processes
- Added dependency on daemontools for setuidgid
- Some misc clean-ups in the spec file itself
- Removed the "setcap" call in the post-install hook; the capability is set by RPM itself
* Thu Jan 31 2013 Philip Homburg <phomburg@ripe.net>
- First real release
* Wed Oct 17 2012 Anand Buddhdev <anandb@ripe.net>
- First version of spec file

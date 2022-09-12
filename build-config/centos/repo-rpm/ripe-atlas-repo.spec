Name:           ripe-atlas-repo
Summary:        RIPE Atlas Software Probe Repo
Version:        1
Release:        3%{?dist}
License:        RIPE NCC
Group:          Applications/Internet
Source1:        ripe-atlas-probe.repo
Source2:        ripe-atlas-probe.pgp
BuildArch:	noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}

%description
Setup the RIPE Atlas Software Probe Repo

%prep

%build

%install
mkdir -p %{buildroot}/etc/yum.repos.d
cp %{SOURCE1} %{buildroot}/etc/yum.repos.d
mkdir -p %{buildroot}/etc/pki/rpm-gpg
cp %{SOURCE2} %{buildroot}/etc/pki/rpm-gpg/ripe-atlas-probe

%clean
rm -rf %{buildroot}

%files
/etc/yum.repos.d
/etc/pki/rpm-gpg/ripe-atlas-probe


%pre

%post

%preun

%postun

%changelog

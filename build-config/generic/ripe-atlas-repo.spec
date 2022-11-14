%define		git_repo         	ripe-atlas-repo
%define		git_branch       	feature/9-evaluate-rpm-package
%define		local_state_dir  	/home/atlas
%define		src_prefix_dir   	/usr/local/atlas
%define		generic_assets_path	build-config/generic

%define         yum_repo_filename       yum.repos.d
%define         gpg_key_filename        RPM-GPG-KEY-ripe-atlas-probe

%define         yum_repo_path           %{_builddir}/%{git_repo}/%{generic_assets_path}/yum.repos.d-generic
%define         gpg_key_path            %{_builddir}/%{git_repo}/%{generic_assets_path}/%{gpg_key_filename}

Name:           ripe-atlas-repo
Summary:        RIPE Atlas Software Probe Repo
Version:        1
Release:        3%{?dist}
License:        RIPE NCC
Group:          Applications/Internet
Source0:        %{_builddir}/%{git_repo}/%{generic_assets_path}/yum.repos.d-generic
Source1:        %{_builddir}/%{git_repo}/%{generic_assets_path}/RPM-GPG-KEY-ripe-atlas-probe
BuildArch:	noarch

%description
Setup the RIPE Atlas Software Probe Repo

%prep
# performing the steps of '%setup' manually since we are pulling from a remote git repo
echo "Cleaning build dir"
cd %{_builddir}
rm -rf %{git_repo}
echo "Getting Sources..."
git clone -b %{git_branch} https://gitlab.ripe.net/atlas/probe/ripe-atlas-software-probe.git %{_builddir}/%{git_repo}
cd %{git_repo}

%build
cat %{yum_repo_path}
sed -i -e "s|baseurl.*$|&%{?dist}|" %{yum_repo_path}

%install
mkdir -p %{buildroot}/etc/yum.repos.d
cp %{yum_repo_path} %{buildroot}/etc/yum.repos.d
mkdir -p %{buildroot}/etc/pki/rpm-gpg
cp %{gpg_key_path} %{buildroot}/etc/pki/rpm-gpg/

%clean
#rm -rf %{buildroot}

%files
/etc/%{yum_repo_filename}
/etc/pki/rpm-gpg/%{gpg_key_filename}

%changelog

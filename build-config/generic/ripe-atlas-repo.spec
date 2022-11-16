%define		git_repo         	ripe-atlas-software-probe
%define		git_branch       	feature/9-evaluate-rpm-package
%define		build_dirname		ripe-atlas-repo
%define		local_state_dir  	/home/atlas
%define		src_prefix_dir   	/usr/local/atlas
%define		generic_assets_path	build-config/generic

%define         yum_repo_filename       yum.repos.d
%define         gpg_key_filename        RPM-GPG-KEY-ripe-atlas-probe

%define         yum_repo_path           %{_builddir}/%{build_dirname}/%{generic_assets_path}/yum.repos.d-generic
%define         gpg_key_path            %{_builddir}/%{build_dirname}/%{generic_assets_path}/%{gpg_key_filename}

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
rm -rf %{build_dirname}
echo "Getting Sources..."
if [[ ! -z "${PROBE_SUBGROUP_USER}" && ! -z "${PROBE_SUBGROUP_TOKEN}" ]] ; then
	git clone -b %{git_branch} https://${PROBE_SUBGROUP_USER}:${PROBE_SUBGROUP_TOKEN}@gitlab.ripe.net/atlas/probe/%{git_repo}.git %{_builddir}/%{build_dirname}
else
	echo "Creditials must be entered manually.. "
	git clone -b %{git_branch} https://gitlab.ripe.net/atlas/probe/%{git_repo}.git %{_builddir}/%{build_dirname}
fi
cd %{build_dirname}

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

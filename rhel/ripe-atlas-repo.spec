%define		git_repo         	ripe-atlas-software-probe
%define		build_dirname		ripe-atlas-repo
%define		local_state_dir  	/home/ripe-atlas
%define		src_prefix_dir   	/usr/local/ripe-atlas
%define		assets_path		build-config/rhel

%define         repofile_dirname	%{_sysconfdir}/yum.repos.d
%define		key_dirname		%{_sysconfdir}/pki/rpm-gpg
%define         gpg_key_filename	RPM-GPG-KEY-ripe-atlas-probe

%define         repofile_path           %{_builddir}/%{build_dirname}/%{assets_path}/ripe-atlas-probe.repo
%define         gpg_key_path            %{_builddir}/%{build_dirname}/%{assets_path}/%{gpg_key_filename}

Name:           ripe-atlas-repo
Summary:        RIPE Atlas Software Probe Repo
Version:        1
Release:        3%{?dist}
License:        RIPE NCC
Group:          Applications/Internet
BuildArch:	noarch

%description
Setup the RIPE Atlas Software Probe Repo

%prep
# performing the steps of '%setup' manually since we are pulling from a remote git repo
echo "Cleaning build dir"
cd %{_builddir}
rm -rf %{_builddir}/%{build_dirname}
echo "Getting Sources..."

%{!?git_tag:%define git_tag master}
%{!?git_source:%define git_source https://github.com/RIPE_NCC}

git clone -b %{git_tag} --recursive %{git_source}/%{git_repo}.git %{_builddir}/%{build_dirname}

cd %{_builddir}/%{build_dirname}
%{?git_commit:git checkout %{git_commit}}

%build
STRIPPED_DIST=$(echo %{?dist} | sed -r 's/^\.//')
if [ -z ${STRIPPED_DIST} ] ; then 
	echo "OS Error: No Distribution Detected! rpm macro ?dist is empty"
	exit 1
fi

echo "OS Distro detected as: ${STRIPPED_DIST}"
sed -i -e "s/baseurl.*\$/&${STRIPPED_DIST}\//" %{repofile_path}

%install
mkdir -p %{buildroot}/{%{repofile_dirname},%{key_dirname}}
install -m 0644 %{repofile_path} %{buildroot}%{repofile_dirname}
install -m 0644 %{gpg_key_path} %{buildroot}%{key_dirname}

%files
%{repofile_dirname}
%{key_dirname}

%changelog


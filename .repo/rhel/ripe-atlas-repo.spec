%define		git_repo         	ripe-atlas-software-probe
%define		base_name		ripe-atlas-repo

%define		repo_dir		%{_sysconfdir}/yum.repos.d
%define		repo_file		ripe-atlas.repo
%define		key_dir			%{_sysconfdir}/pki/rpm-gpg
%define		key_file		RPM-GPG-KEY-ripe-atlas

%define		repo_path		%{_builddir}/%{base_name}/%{repo_file}
%define		key_path		%{_builddir}/%{base_name}/%{key_file}

Name:           ripe-atlas-repo
Summary:        RIPE Atlas Software Probe Repo
Version:        1
Release:        5%{?dist}
License:        RIPE NCC
Group:          Applications/Internet
BuildArch:	noarch

%description
Setup the RIPE Atlas Software Probe Repo

%prep
# performing the steps of '%setup' manually since we are pulling from a remote git repo
echo "Cleaning build dir"
cd %{_builddir}
rm -rf %{_builddir}/%{base_name}
echo "Getting Sources..."

%{!?git_tag:%define git_tag master}
%{!?git_source:%define git_source https://github.com/RIPE_NCC}

git clone -b %{git_tag} %{git_source}/%{git_repo}.git %{_builddir}/%{base_name}

cd %{_builddir}/%{base_name}
%{?git_commit:git checkout %{git_commit}}

%build
RELEASE='%{git_tag}'
RELEASE="${RELEASE%%%.*}"
case "${RELEASE}" in
	([0-9]*)
		RELEASE='master'
		;;

	master)
		;;

	*)
		sed -i -e "s/baseurl.*\$/&.${RELEASE}\//" %{repo_path}
		;;
esac

STRIPPED_DIST="$(echo %{?dist} | sed -r 's/^\.//')"
if [ -z "${STRIPPED_DIST}" ] ; then
	echo "OS Error: No Distribution Detected! rpm macro ?dist is empty"
	exit 1
fi

echo "OS Distro detected as: ${STRIPPED_DIST}"
sed -i -e "s/baseurl.*\$/&${STRIPPED_DIST}\//" %{repo_path}

%install
RELEASE='%{git_tag}'
RELEASE="${RELEASE%%%.*}"
case "${RELEASE}" in
	([0-9]*)
		RELEASE='master'
		;;

	*)
		;;
esac
mkdir -p %{buildroot}/{%{repo_dir},%{key_dir}}
install -m 0644 %{repo_path} %{buildroot}%{repo_dir}
install -m 0644 "%{key_path}.${RELEASE}" %{buildroot}%{key_dir}/%{key_file}

%files
%{repo_dir}/*
%{key_dir}/*
%exclude %dir %{repo_dir}
%exclude %dir %{key_dir}

%include rhel/changelog


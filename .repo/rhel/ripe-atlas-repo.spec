%define		git_repo         	ripe-atlas-software-probe
%define		base_name		ripe-atlas-repo

%define		repo_dir		%{_sysconfdir}/yum.repos.d
%define		repo_file		ripe-atlas.repo
%define		key_dir			%{_sysconfdir}/pki/rpm-gpg
%define		newkey_file		RPM-GPG-KEY-ripe-atlas-20240924

%define		source_path		%{_builddir}/%{base_name}/.repo
%define		repo_path		%{source_path}/%{repo_file}

%define		repo_majver		%(find . -name REPO_MAJVER | head -1 | xargs -I {} sh -c "cat {}")
%define		repo_minver		%(find . -name REPO_MINVER | head -1 | xargs -I {} sh -c "cat {}")

Name:           ripe-atlas-repo
Summary:        RIPE Atlas Software Probe Repo
Version:        %{repo_majver}
Release:        %{repo_minver}%{?dist}
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
%{!?git_source:%define git_source https://github.com/RIPE-NCC}

git clone -b %{git_tag} %{git_source}/%{git_repo}.git %{_builddir}/%{base_name}

cd %{_builddir}/%{base_name}
%{?git_commit:git checkout %{git_commit}}

%build
case %{git_tag} in
	# incl. release tags (e.g. 5120)
	[0-9]*|master)
        RELEASE='master'
        ;;
    testing*)
        RELEASE='testing'
        ;;
    devel*|*)
        RELEASE='devel'
esac

# Append release channel to repo url if needed
case "${RELEASE}" in
	master)
		;;
	testing|devel)
		# (...)/software-probe/.testing/ and (...)/software-probe/.devel/ for testing/devel releases
		sed -i -e "s/baseurl.*\$/&.${RELEASE}\//" %{repo_path}
		;;
	*)
		echo "Unknown release" >&2
		exit 1
esac

# Add /rhel/ to URL
sed -i -e "s/baseurl.*\$/&rhel\//" %{repo_path}

STRIPPED_DIST="$(echo %{?dist} | sed -r 's/^\.//')"
if [ -z "${STRIPPED_DIST}" ] ; then
	echo "OS Error: No Distribution Detected! rpm macro ?dist is empty"
	exit 1
fi

echo "OS Distro detected as: ${STRIPPED_DIST}"
# Add /el[:digit:]/ to URL
sed -i -e "s/baseurl.*\$/&${STRIPPED_DIST}\//" %{repo_path}

%install

case %{git_tag} in
	# incl. release tags (e.g. 5120)
	[0-9]*|master)
        RELEASE='master'
        ;;
    testing*)
        RELEASE='testing'
        ;;
    devel*|*)
        RELEASE='devel'
esac

mkdir -p %{buildroot}/{%{repo_dir},%{key_dir}}
install -m 0644 %{repo_path} %{buildroot}%{repo_dir}
install -m 0644 "%{source_path}/%{newkey_file}.${RELEASE}" %{buildroot}%{key_dir}/%{newkey_file}

%files
%{repo_dir}/*
%{key_dir}/*
%exclude %dir %{repo_dir}
%exclude %dir %{key_dir}

%include rhel/changelog


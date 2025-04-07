# Building instructions

## Introduction

While we do provide binary packages, your conditions may require you to build the software probe yourself. This document provides instructions for building the software probe on various platforms.

The source code can build 4 different packages:

- `ripe-atlas-common`: contains all of the **common code** between probe and anchors
- `ripe-atlas-probe`: contains **probe-specific configuration**
- `ripe-atlas-anchor`: contains **anchor-specific configuration**
- `ripe-atlas-repo`: sets up the RIPE Atlas **repository**

> [!IMPORTANT]
> The `ripe-atlas-anchor` package is intended for deploying Atlas anchors.
>
> Please install ***only*** when instructed to do so by RIPE NCC staff.

> [!TIP]
> It is not required to install `sudo`, even though the instructions might make use of it; having root privileges is sufficient.

## Enterprise Linux

We provide RPMs for `amd64` EL8 and EL9, as shown in [README.md](README.md#enterprise-linux). To manually build an RPM package, we provide the following instructions

```sh
# Building dependencies
sudo dnf update && sudo dnf install git tar rpm-build systemd openssl-devel autoconf automake libtool make
git clone https://github.com/RIPE-NCC/ripe-atlas-software-probe.git
pushd ripe-atlas-software-probe

# Building the packages
rpmbuild --bb rhel/ripe-atlas-probe.spec
rpmbuild --bb rhel/ripe-atlas-anchor.spec
pushd .repo
rpmbuild --bb rhel/ripe-atlas-repo.spec
popd
popd

# Installing the probe package
pushd ~/rpmbuild/RPMS
sudo dnf -y install */ripe-atlas-common*.rpm noarch/ripe-atlas-probe*.rpm
# Follow the instructions printed after installation to start and register and your probe
popd
```

> [!NOTE]
> If you wish to build a specific branch or repository, you can define the following macros:
>
> | Macro | Description | Default |
> | --- | --- | --- |
> | `git_source` | Specify a git repository | `--define "git_source https://github.com/RIPE-NCC` |
> | `git_tag` | Specify a particular branch | `--define "git_tag master"` |
> | `git_commit` | Specify a particular commit hash | |
>

> [!TIP]
> The signed packages we provide can be verified using `rpm`:
> ```sh
> rpm --import /etc/pki/rpm-gpg/*ripe-atlas*
> rpm -K ./ripe-atlas*.rpm
> ```
> This can **only** be done after the `ripe-atlas-repo` package has been installed.

## Debian / RPi OS

We provide DEBs for `amd64` Debian 11 & 12 and `arm64` for Raspberry Pi OS 12 (cross-built from `amd64` Debian 12), as shown in [README.md](README.md#debian--raspberry-pi-os). To manually build a DEB package, we provide the following instructions:

```sh
# Building dependencies
sudo apt-get update && sudo apt-get -y install git build-essential debhelper libssl-dev autotools-dev psmisc net-tools systemd
git clone https://github.com/RIPE-NCC/ripe-atlas-software-probe.git
pushd ripe-atlas-software-probe
git checkout master

# Building the packages
dpkg-buildpackage -b -us -uc
cp ../ripe-atlas-*.deb .
pushd .repo
dpkg-buildpackage -b -us -uc
popd

# Installing the probe package
sudo dpkg -i ripe-atlas-common*.deb ripe-atlas-probe*.deb
# Follow the instructions printed after installation to start and register and your probe
popd
```

> [!TIP]
> The signed packages we provide can be verified using `debsig-verify`:
> ```sh
> debsig-verify ./ripe-atlas-probe_*.deb
> ```
> This can **only** be done after the `ripe-atlas-repo` package has been installed.

> [!TIP]
> If you have an error mentioning `setcap: not found`, you can install the `libcap2-bin` package:
> ```sh
> apt-get install libcap2-bin
> ```
> This will be fixed in a future release.

## OpenWRT

These instructions make use of OpenWRT's build system. This has been tested for OpenWRT 22.03, which will be fully supported in an upcoming release.

Add the following line as a feed in `feeds.conf`:

```text
src-git ripeatlas https://github.com/RIPE-NCC/ripe-atlas-software-probe.git
```

Then run `scripts/feeds install -a` from the toplevel OpenWRT directory.

The default branch checked out is master, other branches can be checked out by appending `;<BRANCH>` or `^commit` to the line. See [the upstream feeds docs](https://openwrt.org/docs/guide-developer/feeds) for more information.

At this point, the package can be selected using `menuconfig` and built as normal.

With `ipkg` files, installation is done as follows:

```sh
opkg install ripe-atlas-common-????.ipkg ripe-atlas-software-probe-????.ipkg
service ripe-atlas enable
service ripe-atlas start
```

## Manual

The software probe can be built and installed manually using `autoconf` tooling, but we recommend against it.

```sh
# Building
autoreconf -iv
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib64 --runstatedir=/run --with-user=ripe-atlas --with-group=ripe-atlas --with-measurement-user=ripe-atlas-measurement --disable-systemd --enable-chown --enable-setcap-install
make
# Installing
sudo make install
sudo /usr/sbin/ripe-atlas
```

# Branching strategy and versioning

## Branches

The repository is structured around 3 main branches, and a topic branch:

- `master` (production-ready)
- `testing`
- `devel`
- Ticket branches

### Branch names

#### `master`

The `master` branch contains the latest production-level code.
The firmware for hardware probes is built from this branch.

#### `testing`

The `testing` branch is a pointer on the `devel` branch.
It contains code that is being prepared for a next production release.

#### `devel`

The `devel` branch contains code which is feature complete, but may not be fully tested yet.
This code is merged into the `testing` branch (through PRs w/ review) upon completion and unit testing, when a next production release is being prepared.

#### Ticket branches

Development work is done on ticket branches that branch off `devel`. Those ticket branches can contain code that is broken.

## Versioning

Any version number divisible by 10 is a production release. (5080, 5090, 5100).
Any other number is either a development or a testing release.

When uncertain, select the `master` branch, it contains the latest production release.

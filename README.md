<p align="center">
  <a href="https://atlas.ripe.net"><img src="https://raw.githubusercontent.com/RIPE-NCC/ripe-atlas-software-probe/master/logo.svg?sanitize=true&raw=true"/></a>
</p>

<p align="center">
  <a href="https://github.com/RIPE-NCC/ripe-atlas-software-probe/releases"><img alt="RIPE Atlas Version" src="https://img.shields.io/github/v/release/RIPE-NCC/ripe-atlas-software-probe?display_name=release&label=version&color=blue&style=flat"></a>
  <img alt="Stable" src="https://img.shields.io/badge/status-stable-brightgreen&style=flat">
  <img alt="License" src="https://img.shields.io/github/license/RIPE-NCC/ripe-atlas-software-probe?color=blue&style=flat">
  <a href="https://atlas.ripe.net/docs/"><img alt="Documentation" src="https://img.shields.io/badge/Docs-blue.svg?style=style=flat&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0NDggNTEyIj48cGF0aCBmaWxsPSIjZmZmZmZmIiBkPSJNMzU2IDE2MEgxODhjLTYuNiAwLTEyLTUuNC0xMi0xMnYtOGMwLTYuNiA1LjQtMTIgMTItMTJoMTY4YzYuNiAwIDEyIDUuNCAxMiAxMnY4YzAgNi42LTUuNCAxMi0xMiAxMnptMTIgNTJ2LThjMC02LjYtNS40LTEyLTEyLTEySDE4OGMtNi42IDAtMTIgNS40LTEyIDEydjhjMCA2LjYgNS40IDEyIDEyIDEyaDE2OGM2LjYgMCAxMi01LjQgMTItMTJ6bTY0LjcgMjY4aDMuM2M2LjYgMCAxMiA1LjQgMTIgMTJ2OGMwIDYuNi01LjQgMTItMTIgMTJIODBjLTQ0LjIgMC04MC0zNS44LTgwLTgwVjgwQzAgMzUuOCAzNS44IDAgODAgMGgzNDRjMTMuMyAwIDI0IDEwLjcgMjQgMjR2MzY4YzAgMTAtNi4yIDE4LjYtMTQuOSAyMi4yLTMuNiAxNi4xLTQuNCA0NS42LS40IDY1Ljh6TTEyOCAzODRoMjg4VjMySDEyOHYzNTJ6bS05NiAxNmMxMy40LTEwIDMwLTE2IDQ4LTE2aDE2VjMySDgwYy0yNi41IDAtNDggMjEuNS00OCA0OHYzMjB6bTM3Mi4zIDgwYy0zLjEtMjAuNC0yLjktNDUuMiAwLTY0SDgwYy02NCAwLTY0IDY0IDAgNjRoMzI0LjN6Ij48L3BhdGg+PC9zdmc+Cg=="></a> <!-- svg taken from atlas.ripe.net/docs -->
</p>
<p align="center">
  <img alt="Runs on" src="https://img.shields.io/badge/Runs_on%3A-grey?style=flat">
  <img alt="Debian Support" src="https://img.shields.io/badge/Debian-A81D33?style=flat&logo=debian&logoColor=white">
  <img alt="Raspberry Pi Support" src="https://img.shields.io/badge/-Raspberry_Pi-C51A4A?style=flat&logo=Raspberry-Pi&logoColor=white">
  <img alt="Enterprise Linux Support" src="https://img.shields.io/badge/Enterprise_Linux-EE0000?style=flat&logo=linux&logoColor=white">
</p>

---

[**RIPE Atlas**](https://atlas.ripe.net/) is a global network of probes that measure Internet connectivity and reachability, providing an unprecedented understanding of the state of the Internet in real time.

This project contains the probe code that powers software probes.

We release binary packages for the `amd64` variants of Debian 11 / 12 / 13, (Oracle) Enterprise Linux 8 / 9 / 10, and `arm64` variant of Raspberry Pi OS 12 / 13.<br>
The source code also allows for building of an OpenWrt 22.03 package.

## Installation

### Debian & Raspberry Pi OS

```sh
# Download: Debian 11 / 12 / 13 & Raspberry Pi OS 12 / 13
ARCH=$(dpkg --print-architecture)
CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
REPO_PKG=ripe-atlas-repo_1.5-5_all.deb
wget https://ftp.ripe.net/ripe/atlas/software-probe/debian/dists/"$CODENAME"/main/binary-"$ARCH"/"$REPO_PKG" https://github.com/RIPE-NCC/ripe-atlas-software-probe/releases/latest/download/CHECKSUMS
grep -q "$(sha256sum "$REPO_PKG")" CHECKSUMS && echo "Success: checksum matches" || ( printf "\n\033[1;31mError: checksum does not match\033[0m\n\n"; rm "$REPO_PKG" )

# Install: Debian 11 / 12 / 13 & Raspberry Pi OS 12 / 13
sudo dpkg -i "$REPO_PKG" && rm "$REPO_PKG"
sudo apt update
sudo apt-get install ripe-atlas-probe
```

### Enterprise Linux

```sh
# Download: Enterprise Linux 8 / 9 / 10
EL_VER=$(. /etc/os-release && echo $PLATFORM_ID | cut -d':' -f2)
REPO_PKG=ripe-atlas-repo-1.5-5."$EL_VER".noarch.rpm
curl -fO -LfO https://ftp.ripe.net/ripe/atlas/software-probe/"$EL_VER"/noarch/"$REPO_PKG" https://github.com/RIPE-NCC/ripe-atlas-software-probe/releases/latest/download/CHECKSUMS
grep -q "$(sha256sum "$REPO_PKG")" CHECKSUMS && echo "Success: checksum matches" || ( printf "\n\033[1;31mError: checksum does not match\033[0m\n\n"; rm "$REPO_PKG" )

# Install: Enterprise Linux 8 / 9 / 10
sudo rpm -Uvh "$REPO_PKG" && rm "$REPO_PKG"
sudo dnf install ripe-atlas-probe
```

### Other platforms

For other platforms, please refer to the [building instructions](BUILD.md).

## Configuration options

Currently there are three runtime configuration options available.
To use them, create the file `/etc/ripe-atlas/config.txt` and add a line per desired configuration setting.

| Configuration | Description | Default |
| --- | --- | --- |
| `RXTXRPT` | Sending interface traffic statistics as Atlas measurement results | `RXTXRPT=no` |
| `TELNETD_PORT` | TCP port used for telnetd | `TELNETD_PORT=2023` |
| `HTTP_POST_PORT` | TCP port used for httppost | `HTTPD_PORT=8080` |

## Upgrading

### v5090 and later

For officially supported and provided packages, use your system's package manager to upgrade the package:

* Debian: `apt update && apt upgrade`
* Enterprise Linux: `dnf upgrade`

### v5080 and earlier (`atlasswprobe`)

Follow the [standard installation instructions](#installation) to upgrade to the latest version.

See [the FAQ](#upgrade-from-atlasswprobe-5080) for more information about the upgrade process and changes.

> [!NOTE]
> We have tested the upgrade process thoroughly, but still recommend backing up your probe key and configuration files before upgrading.

## FAQ

### Generic installation instructions

The public key is stored in `/etc/ripe-atlas/probe_key.pub`. Use it to register your probe at <https://atlas.ripe.net/apply/swprobe/>.

### TCP ports conflict

The software probe uses TCP ports 2023 and 8080 internally.
If another service is using these ports then the probe will not function correctly.
To avoid conflicts, [runtime configuration options](#configuration-options) can be used to make the probe use different port numbers.

### Upgrading from 5080 and earlier

#### Automatic updates

Starting with release 5080 (September 2022), the package will no longer automatically update.

The intent of this decision is to conform to operational practices and to make deployment and maintenance easier on hosts (and the Atlas team).
If you wish to keep automatically updating your software probe, please install the automatic update package of your choice.

Suggested solutions available are `yum-cron`, `dnf-automatic` or `unattended-upgrades`.

#### Upgrade from `atlasswprobe` (5080)

To upgrade from 5080 on Debian, or on older non-repo Enterprise Linux versions, you can follow [the standard installation instructions](#installation).

Upgrading from `atlasswprobe` will attempt to migrate existing probe keys and configuration, while existing state in `/var/altas-probe/` will be removed, as the big change in 5090 was towards a more FHS compliant structure, moving away from `/var/atlas-probe/`.

Due to the changes, even though we have tested the upgrade process thoroughly, we still recommend backing up your probe key and configuration files before upgrading.

> [!CAUTION]
> Removing `atlasswprobe` will remove data within `/var/atlas-probe`, including your key and configuration
>
> As such, **install the new version** instead of removing the old one and installing the new one. The old version will automatically be removed.

> [!TIP]
> If you did remove the old version, **your original key has been deleted** and a new one has been generated.
> Your new key will have been printed during the installation, but you can also find it in `/etc/ripe-atlas/probe_key.pub`.
>
> To update your key, go to [your probes page on atlas.ripe.net](https://atlas.ripe.net/probes/mine), click on the respective probe ID, and click on "Manage". On this page, you can update the SSH key of your probe.
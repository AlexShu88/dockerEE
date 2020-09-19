%global debug_package %{nil}


Name: docker-ee
Version: %{_version}
Release: %{_release}%{?dist}
Epoch: 3
Source0: engine.tgz
Source1: docker.service
Source2: docker.socket
Summary: The open-source application container engine
Group: Tools/Docker
License: Docker EUSA
URL: https://www.docker.com
Vendor: Docker
Packager: Docker <support@docker.com>

Requires: docker-ee-cli

# container-selinux isn't a thing in suse flavors
%if %{undefined suse_version}
# amazonlinux2 doesn't have container-selinux either
%if "%{?dist}" != ".amzn2"
# Resolves: rhbz#1165615
Requires: device-mapper-libs >= 1.02.90-1
Requires: container-selinux >= 2:2.74
%endif
%endif

# SLES only has libseccomp2
%if %{defined suse_version}
Requires: libseccomp2 >= 2.3
%else
Requires: libseccomp >= 2.3
%endif

Requires: systemd
%if 0%{?rhel} >= 8
Requires: iptables or nftables
%else
Requires: iptables
%endif
%if %{undefined suse_version}
Requires: libcgroup
%endif
Requires: containerd.io
Requires: tar
Requires: xz

%if %{undefined suse_version}
%if 0%{?rhel} < 8
BuildRequires: btrfs-progs-devel
%endif
BuildRequires: glibc-static
BuildRequires: libtool-ltdl-devel
BuildRequires: pkgconfig(systemd)
BuildRequires: selinux-policy-devel
%else
BuildRequires: glibc-devel-static
BuildRequires: libbtrfs-devel
BuildRequires: libltdl7
BuildRequires: systemd
%endif

BuildRequires: ca-certificates
BuildRequires: cmake
BuildRequires: device-mapper-devel
BuildRequires: gcc
BuildRequires: git
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: libtool
BuildRequires: make
BuildRequires: pkgconfig
BuildRequires: systemd-devel
BuildRequires: tar
BuildRequires: which

# conflicting packages
Conflicts: docker
Conflicts: docker-io
Conflicts: docker-engine-cs

# Obsolete packages
Obsoletes: docker-ce
Obsoletes: docker-ce-selinux
Obsoletes: docker-ee-selinux
Obsoletes: docker-engine-selinux
Obsoletes: docker-engine

%description
Docker is a product for you to build, ship and run any application as a
lightweight container.

Docker containers are both hardware-agnostic and platform-agnostic. This means
they can run anywhere, from your laptop to the largest cloud compute instance and
everything in between - and they don't require you to use a particular
language, framework or packaging system. That makes them great building blocks
for deploying and scaling web apps, databases, and backend services without
depending on a particular stack or provider.

Docker EUSA https://www.docker.com/docker-software-end-user-subscription-agreement

%prep
%setup -q -c -n src -a 0

%build

export DOCKER_GITCOMMIT=%{_engine_gitcommit}
mkdir -p /go/src/github.com/docker
ln -s /root/rpmbuild/BUILD/src/engine /go/src/github.com/docker/docker

pushd engine
for component in tini "proxy dynamic";do
    TMP_GOPATH="/go" hack/dockerfile/install/install.sh $component || exit 1;
done
VERSION=%{_origversion} PRODUCT=docker hack/make.sh dynbinary
popd

%check
engine/bundles/dynbinary-daemon/dockerd -v

%install
# install daemon binary
install -D -p -m 0755 $(readlink -f engine/bundles/dynbinary-daemon/dockerd) $RPM_BUILD_ROOT/%{_bindir}/dockerd

# install proxy
install -D -p -m 0755 /usr/local/bin/docker-proxy $RPM_BUILD_ROOT/%{_bindir}/docker-proxy

# install tini
install -D -p -m 755 /usr/local/bin/docker-init $RPM_BUILD_ROOT/%{_bindir}/docker-init

# install systemd scripts
install -D -m 0644 %{_topdir}/SOURCES/docker.service $RPM_BUILD_ROOT/%{_unitdir}/docker.service
install -D -m 0644 %{_topdir}/SOURCES/docker.socket $RPM_BUILD_ROOT/%{_unitdir}/docker.socket

%files
/%{_bindir}/dockerd
/%{_bindir}/docker-proxy
/%{_bindir}/docker-init
/%{_unitdir}/docker.service
/%{_unitdir}/docker.socket

%post
%systemd_post docker.service
if ! getent group docker > /dev/null; then
    groupadd --system docker
fi

%preun
%systemd_preun docker.service

%postun
%systemd_postun_with_restart docker.service

%changelog

Name:               yaca
Version:            0.0.1
Release:            0
Source0:            %{name}-%{version}.tar.gz
License:            Apache-2.0
Group:              Security/Other
Summary:            Yet Another Crypto API
BuildRequires:      cmake
BuildRequires:      pkgconfig(openssl)
Requires(post):     /sbin/ldconfig
Requires(postun):   /sbin/ldconfig

%description
The package provides Yet Another Crypto API.

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%{_libdir}/libyaca.so.0
%{_libdir}/libyaca.so.%{version}

%prep
%setup -q

%build
%{!?build_type:%define build_type "RELEASE"}

%cmake . -DCMAKE_BUILD_TYPE=%{build_type}
make -k %{?jobs:-j%jobs}

%install
%make_install

%clean
rm -rf %{buildroot}

## Devel Package ###############################################################
%package devel
Summary:        Yet Another Crypto API development files
Group:          Security/Other
Requires:       yaca = %{version}-%{release}

%description devel
The package provides Yet Another Crypto API development files.

%files devel
%{_libdir}/libyaca.so
%{_includedir}/yaca
%{_libdir}/pkgconfig/yaca.pc

## Examples Package ############################################################
%package examples
Summary:        Yet Another Crypto API example files
Group:          Security/Other
Requires:       yaca = %{version}-%{release}

%description examples
The package provides Yet Another Crypto API example files.

%files examples
%{_bindir}/yaca-example*
%{_datadir}/%{name}/examples

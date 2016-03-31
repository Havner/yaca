Name:               owl
Version:            0.0.1
Release:            0
Source0:            %{name}-%{version}.tar.gz
License:            Apache-2.0
Group:              Security/Other
Summary:            Openssl wrapper layer
BuildRequires:      cmake
BuildRequires:      pkgconfig(openssl)
Requires(post):     /sbin/ldconfig
Requires(postun):   /sbin/ldconfig

%description
The package provides Openssl wrapper layer.

%files
%defattr(644,root,root,755)
%{_libdir}/libowl.so.0
%attr(755,root,root) %{_libdir}/libowl.so.%{version}

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

%post -n owl -p /sbin/ldconfig

%postun -n owl -p /sbin/ldconfig

## Devel Package ###############################################################
%package devel
Summary:        Development Openssl wrapper layer
Group:          Security/Other
Requires:       owl = %{version}-%{release}

%description devel
The package provides Openssl wrapper development layer.

%files devel
%defattr(644,root,root,755)
%{_libdir}/libowl.so
%{_includedir}/owl
%{_libdir}/pkgconfig/owl.pc

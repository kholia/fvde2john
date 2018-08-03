Name: libfvde
Version: 20180108
Release: 1
Summary: Library to access the FileVault Drive Encryption (FVDE) format
Group: System Environment/Libraries
License: LGPL
Source: %{name}-%{version}.tar.gz
URL: https://github.com/libyal/libfvde
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires:         openssl          zlib
BuildRequires:         openssl-devel          zlib-devel

%description
Library to access the FileVault Drive Encryption (FVDE) format

%package devel
Summary: Header files and libraries for developing applications for libfvde
Group: Development/Libraries
Requires: libfvde = %{version}-%{release}

%description devel
Header files and libraries for developing applications for libfvde.

%package python
Summary: Python 2 bindings for libfvde
Group: System Environment/Libraries
Requires: libfvde = %{version}-%{release} python
BuildRequires: python-devel

%description python
Python 2 bindings for libfvde

%package python3
Summary: Python 3 bindings for libfvde
Group: System Environment/Libraries
Requires: libfvde = %{version}-%{release} python3
BuildRequires: python3-devel

%description python3
Python 3 bindings for libfvde

%package tools
Summary: Several tools for reading FileVault Drive Encryption volumes
Group: Applications/System
Requires: libfvde = %{version}-%{release} fuse-libs
BuildRequires: fuse-devel

%description tools
Several tools for reading FileVault Drive Encryption volumes

%prep
%setup -q

%build
%configure --prefix=/usr --libdir=%{_libdir} --mandir=%{_mandir} --enable-python2 --enable-python3
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%make_install

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(644,root,root,755)
%license COPYING
%doc AUTHORS README
%attr(755,root,root) %{_libdir}/*.so.*

%files devel
%defattr(644,root,root,755)
%license COPYING
%doc AUTHORS README ChangeLog
%{_libdir}/*.a
%{_libdir}/*.la
%{_libdir}/*.so
%{_libdir}/pkgconfig/libfvde.pc
%{_includedir}/*
%{_mandir}/man3/*

%files python
%defattr(644,root,root,755)
%license COPYING
%doc AUTHORS README
%{_libdir}/python2*/site-packages/*.a
%{_libdir}/python2*/site-packages/*.la
%{_libdir}/python2*/site-packages/*.so

%files python3
%defattr(644,root,root,755)
%license COPYING
%doc AUTHORS README
%{_libdir}/python3*/site-packages/*.a
%{_libdir}/python3*/site-packages/*.la
%{_libdir}/python3*/site-packages/*.so

%files tools
%defattr(644,root,root,755)
%license COPYING
%doc AUTHORS README
%attr(755,root,root) %{_bindir}/*
%{_mandir}/man1/*

%changelog
* Mon Jan  8 2018 Joachim Metz <joachim.metz@gmail.com> 20180108-1
- Auto-generated


%define name		jass
%define release		1
%define version 	1.4
%define mybuilddir	${HOME}/redhat/BUILD/%{name}-%{version}-root

Requires:		bash, coreutils, gawk, openldap-clients, openssh >= 5.6, openssl, sharutils
BuildRoot:		%{mybuilddir}
BuildArch:		noarch
Summary:		secret sharing utility
License: 		BSD
Name: 			%{name}
Version: 		%{version}
Release: 		%{release}
Source: 		%{name}-%{version}.tar.gz
Prefix: 		/usr
Group: 			Development/Tools

%description
The jass tools allows you to share a secret with other people through the
use of SSH keypairs.  It accepts input on stdin and generates ciphertext
on stdout, encrypted for the given key or user.

%prep
%setup -q

%build
mkdir -p %{mybuilddir}/usr/bin
mkdir -p %{mybuilddir}/usr/share/man/man1

%install
install -c -m 755 src/jass %{mybuilddir}/usr/bin/jass
install -c -m 444 doc/jass.1 %{mybuilddir}/usr/share/man/man1/jass.1

%files
%defattr(0444,root,root)
%attr(0755,root,root) /usr/bin/jass
%doc /usr/share/man/man1/jass.1.gz

%changelog

# Next version:
#-  man page improvements from kimor79

* Wed Apr 17 2013 - jschauma@netmeister.org
- 1.4:
-  more portability fixes
-  prep documentation and code for public release

* Tue Apr 16 2013 - jschauma@netmeister.org
- 1.3:
-  portability fixes
-  more specific dependencies

* Fri Apr 12 2013 - jschauma@netmeister.org
- 1.2:
-  allow multiple recipients and multiple keys when encrypting data
- 1.1:
-  allow users to specify the input filename

* Wed Apr 10 2013 - jschauma@netmeister.org
- 1.0:
-  generate a session key, then use that to encrypt the data
-  change output format to be two uuencoded files

* Tue Apr 02 2013 - jschauma@netmeister.org
- 0.1:
-  initial version

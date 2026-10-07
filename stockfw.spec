Name: 		stockfw
Version: 	1.0.3
Release: 	1
Epoch:          0
Summary: 	The StockFW firewall tool for GNOME

Group: 		Applications/Internet
License: 	GPL
Source0:	http://stockfw.sourceforge.net/beta/1.0/stockfw-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	glib2-devel >= 0:2.4
BuildRequires:	gtk2-devel >= 0:2.4
BuildRequires:	gnome-vfs2-devel >= 0:2.6.0
BuildRequires:	libglade2-devel >= 0:2.3.6
BuildRequires:	libgnomeui-devel
BuildRequires:  perl-XML-Parser
BuildRequires:	gettext
BuildRequires:  desktop-file-utils

Requires:       iptables
Requires:       usermode-gtk
Requires:       gtk2 >= 2.4.0
Requires:       gnome-vfs2 => 2.6.0
Requires(post):  GConf2
Requires(preun): GConf2

%description
StockFW is an easy-to-use, yet powerful, Linux firewall tool for GNOME.
Use it to quickly set up a secure environment using the firewall creation
wizard, or use it's monitoring and administrating features with your old
firewall scripts.


%prep
%setup -q -n stockfw-%{version}


%build
%configure
make %{?_smp_mflags}


%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/%{_bindir}
mkdir -p ${RPM_BUILD_ROOT}/%{_sbindir}
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/inbound
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound
export GCONF_DISABLE_MAKEFILE_SCHEMA_INSTALL=1
make install DESTDIR=${RPM_BUILD_ROOT}

mv ${RPM_BUILD_ROOT}/%{_bindir}/stockfw ${RPM_BUILD_ROOT}/%{_sbindir}
ln -s %{_bindir}/consolehelper ${RPM_BUILD_ROOT}/%{_bindir}/stockfw

touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/configuration
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/events-filter-hosts
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/events-filter-ports
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/stockfw.sh
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/firewall
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/sysctl-tuning
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/user-pre
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/user-post
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/inbound/allow-from
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/inbound/allow-service
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/inbound/forward
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/inbound/setup
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound/allow-from
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound/allow-service
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound/allow-to
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound/deny-from
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound/deny-service
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound/deny-to
touch ${RPM_BUILD_ROOT}/%{_sysconfdir}/stockfw/outbound/setup

%find_lang %{name}

install -p -D -m0644 stockfw.pam ${RPM_BUILD_ROOT}%{_sysconfdir}/pam.d/stockfw 
install -p -D -m0644 stockfw.console  ${RPM_BUILD_ROOT}%{_sysconfdir}/security/console.apps/stockfw
install -p -D -m0755 fedora.init ${RPM_BUILD_ROOT}%{_initrddir}/stockfw

rm -f ${RPM_BUILD_ROOT}%{_datadir}/gnome/apps/Internet/stockfw.desktop
desktop-file-install --vendor fedora                   \
  --dir ${RPM_BUILD_ROOT}%{_datadir}/applications      \
  --add-category X-Fedora                              \
  stockfw.desktop

                                                                             
%clean
rm -rf ${RPM_BUILD_ROOT}


%post
export GCONF_CONFIG_SOURCE="$(gconftool-2 --get-default-source)"
gconftool-2 --makefile-install-rule %{_sysconfdir}/gconf/schemas/%{name}.schemas &>/dev/null
if [ "$1" = "1" ]; then
        /sbin/chkconfig --level 0123456 iptables off 2>/dev/null || :
        /sbin/chkconfig --add stockfw
        /sbin/chkconfig stockfw on
fi


%preun
if [ "$1" = "0" ]; then
	export GCONF_CONFIG_SOURCE="$(gconftool-2 --get-default-source)"
	gconftool-2 --makefile-uninstall-rule %{_sysconfdir}/gconf/schemas/%{name}.schemas &>/dev/null

	/sbin/chkconfig iptables reset 2>/dev/null || :
	/sbin/service stockfw stop >/dev/null 2>&1
	/sbin/chkconfig --del stockfw
fi


%postun
if [ "$1" = "0" ]; then
    if [ -e /etc/dhclient-exit-hooks ]; then
        grep -v 'sh %{_sysconfdir}/stockfw/firewall.sh start' < /etc/dhclient-exit-hooks > /etc/dhclient-exit-hooks.tmp
        mv /etc/dhclient-exit-hooks.tmp /etc/dhclient-exit-hooks
    fi
fi


%files -f %{name}.lang
%defattr(-,root,root,-)
%doc README ChangeLog AUTHORS TODO COPYING CREDITS
%attr(755,root,root) %{_sbindir}/stockfw
%{_bindir}/stockfw
%config %{_initrddir}/stockfw
%{_sysconfdir}/gconf/schemas/stockfw.schemas
%{_sysconfdir}/pam.d/stockfw
%{_sysconfdir}/security/console.apps/%{name}
%dir %attr(700,root,root) %{_sysconfdir}/stockfw
%dir %attr(700,root,root) %{_sysconfdir}/stockfw/inbound
%dir %attr(700,root,root) %{_sysconfdir}/stockfw/outbound
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/configuration
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/events-filter-hosts
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/events-filter-ports
%config(missingok,noreplace) %attr(700,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/stockfw.sh
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/firewall
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/sysctl-tuning
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/user-pre
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/user-post
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/inbound/*
%config(missingok,noreplace) %attr(400,root,root) %verify(not md5 mode mtime size) %{_sysconfdir}/stockfw/outbound/*
%{_sysconfdir}/stockfw/non-routables
%{_datadir}/applications/fedora-stockfw.desktop
%{_datadir}/pixmaps/*
%{_datadir}/stockfw/*

%changelog
* Don't uninstall schema in preun if we're doing an upgrade

- Reintroduced gtk and gnome-vfs dependencies to keep package from installing
  on old distros where shared libraries detection doesn't work

- New libglade2-devel dependency
- Added glade data files to files section

- Removed ipchains check
- Updated dhclient-exit-hooks hook
- Init script renamed

* Sun Aug 29 2004 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.9-0.fdr.0.1.b1
- 0.9.9b1.

* Thu May 06 2004 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.3-0.fdr.2
- GCONF_DISABLE_MAKEFILE_SCHEMA_INSTALL=1 (#1570)

* Tue May 04 2004 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.3-0.fdr.1
- Update to 0.9.3.
- Install/Uninstall schemas in post/preun.
- Req(post,preun) GConf2.

* Wed Oct 01 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.9
- Removed aesthetic comments.
- Corrected permissions of source files.
- Brought spec more in line with current template.

* Wed Aug 13 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.8
- Added patch to reconginze Linux 2.6 kernels.
- Added patch to fix crash on KDE3 tray updates.

* Wed Aug 06 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.7
- For %%{_sysconfdir}/stockfw now using verify, not ghost.

* Tue Aug 05 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.6
- Cleanup is now done in postun (rather than post, which is silly).

* Sat Aug 02 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.5
- Remove stockfw references from /etc/dhclient-exit-hooks in post.

* Mon Jul 28 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.4
- Fixed Pam typo.
- ghost config files.

* Thu Jul 24 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.3
- Req usermode-gtk.
- Wrapped post script.
- pam_xauth entry -> optional.

* Fri Jul 18 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.2-0.fdr.2
- Readded Epoch: 0.
- Split pam.d and console.apps files into separate SOURCE files.
- Removed hard-coded paths.
- Added explicit epochs.
- Added Req iptables.
- Package now owns %%{_sysconfdir}/stockfw.

* Fri Jun 13 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0.9.2-0.fdr.1
- Updated to 0.9.2.
- Removed Epoch:0.
- buildroot -> RPM_BUILD_ROOT.

* Tue Apr 01 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0:0.9.1-0.fdr.7
- Added desktop-file-utils to BuildRequires.
- Changed category to X-Fedora-Extra.
- Added Epoch:0.

* Tue Mar 25 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0.9.1-0.fdr.6
- removed %postun.

* Tue Mar 25 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0.9.1-0.fdr.5
- Moved menu entry to System Tools.
- removed redundant ldconfig.
- removed extra chkconfig.

* Mon Mar 24 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0.9.1-0.fdr.4
- Made the .desktop file an external file.
- corrected BuildRequires.
- corrected %files

* Wed Mar 08 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0.9.1-0.fdr.3
- Cleaned up spec

* Wed Mar 05 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0.9.1-0.fdr.2
- Cleaned up spec

* Wed Feb 26 2003 Phillip Compton <pcompton[AT]proteinmedia.com> 0.9.1-1.fedora.1
- Initial Fedora release (0.9.1). 

- Updated requirements to GNOME2 level
- Removed all requirements related to the documentation generation

- Merged some compatible cleanups from the FreshRPMS (http://freshrpms.net)
  specfile.
  
- build dependancy cleanups

- gnome-doc-tools is no longer required to build the RPM

- Clean up specfile, and use rpm4 macros
- Remove docuementation tools as requirements
- Add gnome-doc-tools and then some as buildprereq
- Add initscripts to prereq
- used %makeinstall macro instead of old make install
- no use specifying runlevels at the commandline, this
  should be specified in the initscripts itself
- Added gnome-core as requirements

- preun now doesn't explicitly delete the init script,
  caused problem with package upgrades.
- Moved the init scripts to external files
  
- Added sgmltools and openjade to build requirements

- Updated build dependancies

- Fixed documentation directory
- Added sysconfdir variable instead of hardcoding /etc

- Significant changes to allow use of consolehelper

- Fixed problem with CFLAGS and LDADD usage of " and `

- First spec file

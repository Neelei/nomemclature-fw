"""Objets de la base par défaut Stormshield (SNS) : jamais renommés, fusionnés ni retirés.

Liste établie sur un export SNS 4.x réel : les 217 premiers services de la section
[Service], ceux ajoutés par les mises à jour du firmware, les 22 protocoles, les réseaux
RFC/IANA, les hôtes de mise à jour Stormshield et les groupes livrés avec le boîtier.
Tout le reste est considéré comme créé par l'administrateur.
"""

from __future__ import annotations

import re

from fwclean.naming import ESPACE

_ADRESSES = frozenset(
    {
        "localhost",
        "members.dyndns.org",
        "checkip.dyndns.org",
        "dns1.google.com",
        "dns2.google.com",
        "dns1.dns0.eu",
        "dns2.dns0.eu",
        "dcp_multicast",
        "ptcp_multicast",
        "goose_multicast_range",
        "sv_multicast_range",
        "rfc3330",
        "rfc5735",
        "IANA_v6_reserved",
    }
)

_MOTIFS_ADRESSES = re.compile(
    r"^(?:rfc3330_|rfc5735_|rfc4291_|IANA_v6_)"
    r"|\.(?:netasq\.com|stormshield\.eu|stormshieldcs\.eu)$"
)

_SERVICES_BASE = """
auth bgp biff bigbrother bittorrent bittorrent_udp bootpc bootps cisco-sccp citrix citrix_udp
chargen chargen_udp cmd conference courier cryptocard daytime daytime_udp discard discard_udp
domain domain_udp echo echo_udp edonkey edonkey_udp efs epmap epmap_udp exec finger ftp
ftp-data ftp_proxy gopher h323 hostname http http_proxy https https_udp icap icq imap imaps
ingreslock ipx irc iso-tsap jabber jabbers kerberos kerberos-adm kerberos-adm_udp kerberos-iv
kerberos_udp klogin knetd kpasswd kpasswd_udp kpop kshell l2tp ldap ldaps login man
mgcp_gateway mgcp_callagent mgcp_backhaul microsoft-ds microsoft-ds_udp microsoft-lsa1
microsoft-lsa2 microsoft-lsa3 microsoft-ts msnmessenger monitor ms-sql-m ms-sql-m_udp ms-sql-s
ms-sql-s_udp mysql nameserver nameserver_udp netbios-dgm netbios-ns netbios-ns_udp netbios-ssn
netnews new-rwho nfsd nicname nntp notes ntalk ntp oracle pcanywhere_data pcanywhere pcmail
phone pop2 pop3 pop3_proxy pops postgresql pptp print-srv printer qotd qotd_udp radacct radius
remotefs rlp rmonitor router rtelnet rtsp rtsp_udp sip sip_udp slp smtp smtp_proxy snmp
snmptrap smux smux_udp socks squid ssdp ssh_udp subversion sunrpc sunrpc_udp syslog systat
t120 talk tacacs tacacs_udp telnet tempo tftp time timed time_udp uucp uucp-path vnc who wins
wins_udp x11 x11_udp xstop yahoomessenger zenworks zebrasrv zebra zebos ripd ripng ospfd bgpd
bittorrent_tcp citrix_tcp citrix-proxy chargen_tcp daytime_tcp discard_tcp dns dns_tcp dns_udp
echo_tcp edonkey_tcp epmap_tcp git gnutella ftps ftps-data oscar ipp ircs kerberos-adm_tcp
kerberos_tcp kpasswd_tcp loopback_proxyssl microsoft-ds_tcp ms-sql-m_tcp ms-sql-s_tcp
nameserver_tcp netbios-ns_tcp nntps pop3s qotd_tcp rtsp_tcp sip_tcp sips smtps smux_tcp
ssl_proxy sunrpc_tcp tacacs_tcp teamspeak_tcp teamspeak_udp teamviewer teamviewer_udp telnets
teredo time_tcp wins_tcp x11_tcp vmware
"""

_SERVICES_FIRMWARE = """
ldap_udp ldap-gc ldap-gcssl ad2003-dyn_tcp ad2008-dyn_tcp microsoft-dfs microsoft-adsoap madcap
agent_ad agent_ts afp afp_udp afp_tcp hkp hkp_udp hkp_tcp modbus opcua smc syslog-conn
syslog-tls ipfix ipfix_secure ethernetip ethernetip_tcp ethernetip_udp iec60870-5-104
ses-srv-log ses-srv-ssl ses-token ses-srv-admin bacnetip profinet-rt profinet-rtm profinet-cm
rdp rdp_tcp rdp_udp hart-ip hart-ip_tcp hart-ip_udp quic_80 quic_443 dot deltav mqtt_tcp
mqtt_udp secure-mqtt_tcp secure-mqtt_udp dlms-cosem_tcp dlms-cosem_udp
"""

_GROUPES_SERVICES = """
full mail web Admin_srv Auth_srv plugins mgcp ssl_srv irc_srv ircs_srv ActiveDirectory2003
ActiveDirectory2008 quic tds ses_srv_in ses_srv_out ses_srv_web
"""

_PROTOCOLES = """
egp eigrp ggp hmp ipip ipv6-nonxt ospf pim rdp rsvp vrrp ipencap igp swipe mobile etherip encap
ipcomp l2tp ipv6encap icmpv6 divert
"""

NATIFS: dict[str, frozenset[str]] = {
    "adresse": _ADRESSES,
    "service": frozenset((_SERVICES_BASE + _SERVICES_FIRMWARE + _GROUPES_SERVICES).split()),
    "protocole": frozenset(_PROTOCOLES.split()),
}


def est_natif(sorte: str, nom: str) -> bool:
    espace = ESPACE.get(sorte, sorte)
    if nom in NATIFS.get(espace, ()):
        return True
    return espace == "adresse" and _MOTIFS_ADRESSES.search(nom) is not None

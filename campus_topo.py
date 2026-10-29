#!/usr/bin/env python3
"""Campus SDN - topologia Mininet (Distribuidora Quetzal).

Uso (como root):
    sudo python3 campus_topo.py            # sin h5
    sudo python3 campus_topo.py --with-h5  # con h5 (extension X1)

Este script NO instala reglas de flujo: solo construye la topologia,
configura los switches (OpenFlow 1.3, modo de falla seguro) y levanta
los servicios HTTP de srv. Toda la logica vive en el controlador.
"""
import argparse
import os
import subprocess
import sys

from mininet.cli import CLI
from mininet.log import info, setLogLevel, warn
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

WWW_DIR = '/tmp/srv_www'      # portal interno (puerto 80)
ADMIN_DIR = '/tmp/srv_admin'  # panel de administracion (puerto 8080)

# (nombre, vlan, ip, mac, gateway)
HOSTS = [
    ('h1',  10, '10.0.10.11/24', '00:00:00:00:10:11', '10.0.10.1'),
    ('h2',  10, '10.0.10.12/24', '00:00:00:00:10:12', '10.0.10.1'),
    ('h3',  20, '10.0.20.21/24', '00:00:00:00:20:21', '10.0.20.1'),
    ('h4',  20, '10.0.20.22/24', '00:00:00:00:20:22', '10.0.20.1'),
    ('srv', 30, '10.0.30.10/24', '00:00:00:00:30:10', '10.0.30.1'),
]
H5 = ('h5', 99, '10.0.99.50/24', '00:00:00:00:99:50', '10.0.99.1')

# (switch, puerto del switch, host)
ACCESS_LINKS = [
    ('s2', 2, 'h1'),
    ('s2', 3, 'h3'),
    ('s3', 2, 'h2'),
    ('s3', 3, 'h4'),
    ('s3', 4, 'srv'),
]
H5_LINK = ('s2', 4, 'h5')


def build(with_h5):
    net = Mininet(controller=None, switch=OVSSwitch, build=False,
                  autoSetMacs=False, autoStaticArp=False)

    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6653)

    # OpenFlow 1.3 unicamente; sin controlador, el switch NO reenvia (secure).
    sw_opts = dict(cls=OVSSwitch, protocols='OpenFlow13', failMode='secure')
    s1 = net.addSwitch('s1', dpid='0000000000000001', **sw_opts)
    s2 = net.addSwitch('s2', dpid='0000000000000002', **sw_opts)
    s3 = net.addSwitch('s3', dpid='0000000000000003', **sw_opts)
    switches = {'s1': s1, 's2': s2, 's3': s3}

    hosts_def = list(HOSTS) + ([H5] if with_h5 else [])
    hosts = {}
    for name, _vlan, ip, mac, gw in hosts_def:
        hosts[name] = net.addHost(name, ip=ip, mac=mac,
                                  defaultRoute='via ' + gw)

    # Troncales (puertos fijos segun la tabla 3.1)
    net.addLink(s1, s2, port1=1, port2=1)
    net.addLink(s1, s3, port1=2, port2=1)

    # Puertos de acceso
    links = ACCESS_LINKS + ([H5_LINK] if with_h5 else [])
    for sw, port, host in links:
        net.addLink(switches[sw], hosts[host], port1=port)

    return net, hosts


def start_services(srv):
    """Portal en :80 (sirve /tmp/srv_www) y panel admin en :8080."""
    os.makedirs(WWW_DIR, exist_ok=True)
    os.makedirs(ADMIN_DIR, exist_ok=True)
    portal_index = os.path.join(WWW_DIR, 'index.html')
    if not os.path.exists(portal_index):
        with open(portal_index, 'w') as f:
            f.write('<h1>Portal interno - Distribuidora Quetzal</h1>\n')
    admin_index = os.path.join(ADMIN_DIR, 'index.html')
    if not os.path.exists(admin_index):
        with open(admin_index, 'w') as f:
            f.write('<h1>Panel de administracion</h1>\n')

    procs = []
    for port, directory in ((80, WWW_DIR), (8080, ADMIN_DIR)):
        procs.append(srv.popen(
            ['python3', '-m', 'http.server', str(port),
             '--bind', '0.0.0.0', '--directory', directory],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    return procs


def main():
    parser = argparse.ArgumentParser(description='Campus SDN - Mininet')
    parser.add_argument('--with-h5', action='store_true',
                        help='agrega h5 en la VLAN 99 (extension X1)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit('Ejecuta este script con sudo.')

    setLogLevel('info')
    net, hosts = build(args.with_h5)
    procs = []
    try:
        net.start()
        if not net.waitConnected(timeout=10):
            warn('*** Algun switch no se conecto al controlador. '
                 'Esta corriendo osken-manager?\n')
        procs = start_services(hosts['srv'])
        info('*** Servicios de srv: portal :80, panel :8080\n')
        CLI(net)
    finally:
        for p in procs:
            p.terminate()
        net.stop()


if __name__ == '__main__':
    main()

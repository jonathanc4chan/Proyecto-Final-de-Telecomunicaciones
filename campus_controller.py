"""Campus SDN - controlador os-ken 3.1.1 (OpenFlow 1.3).

Version final: segmentacion VLAN (R2), ruteo inter-VLAN (R3), politica de
seguridad (R4), ping al gateway (X2) y red de invitados con limite de
2 Mbps (X1).

Al conectarse cada switch, el controlador borra sus reglas previas (R6) e
instala las de su rol. Las reglas de la VLAN 99 (invitados) se instalan
siempre; si h5 no existe en la topologia, simplemente no reciben trafico.
s2 y s3 usan las mismas reglas de VLAN:
  - puerto de acceso (sin etiqueta) -> se agrega 802.1Q y sale por el troncal,
  - troncal (con etiqueta)          -> se quita 802.1Q y sale a los puertos de
                                       acceso de esa VLAN,
  - cualquier otra cosa             -> se descarta (no hay table-miss).

s1 (nucleo) usa tres tablas:

  Tabla 0 (entrada)
    prio 300  ARP request por la IP del gateway de la VLAN -> controlador.
              Regla REACTIVA: el controlador contesta con 02:00:00:00:00:01.
    prio 250  ICMP echo request a la IP del gateway de la VLAN -> controlador
              (X2, REACTIVA): el controlador contesta con un echo reply.
    prio 200  IPv4 dirigido a la MAC del gateway -> tabla 1.
    prio 150  cualquier otra trama dirigida a la MAC del gateway -> descartar.
    prio  10  reenvio L2 entre los dos troncales (misma VLAN, sin ruteo).
  Tabla 1 (politica / ACL, R4 y X1) - PROACTIVA y sin estado
    prio 100  trafico autorizado por la matriz -> tabla 2. El de la VLAN de
              invitados (X1), en ambos sentidos, pasa antes por el meter 1
              (2 Mbps, descarta el exceso).
    prio  50  celdas denegadas de la matriz -> descartar (un contador por celda).
    prio   0  todo lo demas -> descartar (denegar por defecto).
  Tabla 2 (ruteo, PROACTIVO)
    prio 100  una regla por (host destino, puerto de entrada), solo para
              tramas etiquetadas: TTL-1, MAC origen = gateway, MAC destino =
              host, VLAN destino y salida.
              Si el host queda detras del mismo troncal por el que llego el
              paquete, se sale con IN_PORT (caso "mismo switch de acceso").
"""
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                       set_ev_cls)
from os_ken.lib.packet import (arp, ether_types, ethernet, icmp, in_proto,
                               ipv4, packet, vlan)
from os_ken.ofproto import ofproto_v1_3

DPID_CORE = 1     # s1
DPID_ACCESS1 = 2  # s2
DPID_ACCESS2 = 3  # s3

ETH_P_8021Q = 0x8100
ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
IPPROTO_ICMP = 1
IPPROTO_TCP = 6

# En s2 y s3 el puerto 1 es el troncal hacia s1.
TRUNK_PORT = 1

# Puertos de acceso por switch: {dpid: {puerto: vlan}}.
# El puerto 4 de s2 es de h5 (VLAN 99, extension X1).
ACCESS_PORTS = {
    DPID_ACCESS1: {2: 10, 3: 20, 4: 99},
    DPID_ACCESS2: {2: 10, 3: 20, 4: 30},
}

# En s1 los puertos 1 (hacia s2) y 2 (hacia s3) son troncales.
CORE_TRUNKS = (1, 2)
VLANS = (10, 20, 30, 99)

# Gateways (plan de direccionamiento 3.2): una IP por VLAN, una sola MAC.
GW_MAC = '02:00:00:00:00:01'
GATEWAYS = {10: '10.0.10.1', 20: '10.0.20.1', 30: '10.0.30.1',
            99: '10.0.99.1'}

# Hosts conocidos (tabla 3.3): nombre -> (vlan, ip, mac, puerto de s1 que
# lleva hacia el switch del host). s2 cuelga del puerto 1 y s3 del puerto 2.
HOSTS = {
    'h1':  (10, '10.0.10.11', '00:00:00:00:10:11', 1),
    'h2':  (10, '10.0.10.12', '00:00:00:00:10:12', 2),
    'h3':  (20, '10.0.20.21', '00:00:00:00:20:21', 1),
    'h4':  (20, '10.0.20.22', '00:00:00:00:20:22', 2),
    'srv': (30, '10.0.30.10', '00:00:00:00:30:10', 2),
    'h5':  (99, '10.0.99.50', '00:00:00:00:99:50', 1),   # X1, detras de s2
}

# Subredes (tabla 3.2) como (red, mascara).
SUBNETS = {
    10: ('10.0.10.0', '255.255.255.0'),
    20: ('10.0.20.0', '255.255.255.0'),
    30: ('10.0.30.0', '255.255.255.0'),
    99: ('10.0.99.0', '255.255.255.0'),
}

# Meter de la VLAN de invitados (X1): 2 Mbps, el exceso se descarta.
METER_GUEST = 1
GUEST_RATE_KBPS = 2000
GUEST_BURST_KB = 200

# Politica R4 (matriz de la seccion 4) y X1, aplicada al trafico ENRUTADO
# entre VLAN. Dentro de una misma VLAN no se enruta y la ACL no interviene.
# Cada entrada es (VLAN origen, VLAN destino, filtro, meter). El filtro es
# None (cualquier IP), 'icmp', ('tcp_dst', puerto) o ('tcp_src', puerto).
ACL_ALLOW = [
    (20, 30, None, None),              # Contabilidad -> Servidores: todo
    (30, 20, None, None),              # Servidores -> Contabilidad: todo
    (10, 30, 'icmp', None),            # Ventas -> Servidores: ICMP
    (10, 30, ('tcp_dst', 80), None),   #   y HTTP (peticiones al puerto 80)
    (30, 10, 'icmp', None),            # Servidores -> Ventas: ICMP
    (30, 10, ('tcp_src', 80), None),   #   y respuestas HTTP (origen puerto 80)
    # X1: los invitados solo usan el portal HTTP (puerto 80) del servidor,
    # y todo su trafico, en ambos sentidos, pasa por el meter de 2 Mbps.
    (99, 30, ('tcp_dst', 80), METER_GUEST),
    (30, 99, ('tcp_src', 80), METER_GUEST),
]
# Celdas denegadas. Se descartarian igual por la regla por defecto; se
# instalan aparte para tener un contador de descartes por celda.
ACL_DENY = [(10, 20), (20, 10), (10, 30), (30, 10),
            (99, 10), (99, 20), (99, 30), (10, 99), (20, 99), (30, 99)]

TABLE_INGRESS = 0
TABLE_ACL = 1
TABLE_ROUTE = 2

PRIO_VLAN = 100      # reglas de VLAN en s2 y s3
PRIO_GW_ARP = 300    # s1, tabla 0: ARP del gateway -> controlador
PRIO_GW_ICMP = 250   # s1, tabla 0: ping al gateway -> controlador (X2)
PRIO_GW_IP = 200     # s1, tabla 0: IPv4 a la MAC del gateway -> tabla 1
PRIO_GW_DROP = 150   # s1, tabla 0: resto de lo dirigido al gateway
PRIO_CORE_L2 = 10    # s1, tabla 0: reenvio L2 entre troncales
PRIO_ACL_ALLOW = 100  # s1, tabla 1: autorizado -> ruteo
PRIO_ACL_DENY = 50    # s1, tabla 1: celdas denegadas -> descartar
PRIO_ACL_DEFAULT = 0  # s1, tabla 1: denegar por defecto
PRIO_ROUTE = 100     # s1, tabla 2


class CampusController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        self.logger.info('Switch conectado: dpid=%s', dp.id)

        self._clear_flows(dp)

        if dp.id == DPID_CORE:
            self._install_core(dp)
            self.logger.info('s1 (nucleo): reglas de ruteo instaladas')
        elif dp.id in ACCESS_PORTS:
            self._install_access_vlans(dp)
            self.logger.info('s%s (acceso): reglas VLAN instaladas', dp.id)
        else:
            self.logger.warning('dpid desconocido: %s', dp.id)

    # ---------------------------------------------------------- s2 y s3
    def _install_access_vlans(self, dp):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        ports = ACCESS_PORTS[dp.id]

        # (a) Puerto de acceso -> troncal. vlan_vid=OFPVID_NONE: solo
        #     tramas sin etiqueta; una trama etiquetada que llegue por un
        #     puerto de acceso no coincide y se descarta.
        for port, vlan_id in ports.items():
            peers = [p for p, v in ports.items()
                     if v == vlan_id and p != port]
            actions = [parser.OFPActionOutput(p) for p in peers]
            actions += [
                parser.OFPActionPushVlan(ETH_P_8021Q),
                parser.OFPActionSetField(
                    vlan_vid=vlan_id | ofp.OFPVID_PRESENT),
                parser.OFPActionOutput(TRUNK_PORT),
            ]
            match = parser.OFPMatch(in_port=port, vlan_vid=ofp.OFPVID_NONE)
            self._add_flow(dp, PRIO_VLAN, match, actions)

        # (b) Troncal -> puertos de acceso de esa VLAN, sin etiqueta.
        for vlan_id in sorted(set(ports.values())):
            out_ports = [p for p, v in ports.items() if v == vlan_id]
            actions = [parser.OFPActionPopVlan()]
            actions += [parser.OFPActionOutput(p) for p in out_ports]
            match = parser.OFPMatch(
                in_port=TRUNK_PORT, vlan_vid=vlan_id | ofp.OFPVID_PRESENT)
            self._add_flow(dp, PRIO_VLAN, match, actions)

    # --------------------------------------------------------------- s1
    def _install_core(self, dp):
        self._install_core_l2(dp)
        self._install_gateway_arp(dp)
        self._install_gateway_icmp(dp)
        self._install_gateway_entry(dp)
        self._install_meters(dp)   # antes de la ACL, que los referencia
        self._install_acl(dp)
        self._install_routes(dp)

    def _install_meters(self, dp):
        """X1: meter de 2 Mbps para la VLAN de invitados.

        Los meters no se borran con los flujos: se eliminan todos antes de
        crear el nuestro para que reconectar un switch no falle por
        'meter ya existe' (R6)."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPMeterMod(
            datapath=dp, command=ofp.OFPMC_DELETE, flags=0,
            meter_id=ofp.OFPM_ALL))
        band = parser.OFPMeterBandDrop(
            rate=GUEST_RATE_KBPS, burst_size=GUEST_BURST_KB)
        dp.send_msg(parser.OFPMeterMod(
            datapath=dp, command=ofp.OFPMC_ADD,
            flags=ofp.OFPMF_KBPS | ofp.OFPMF_BURST | ofp.OFPMF_STATS,
            meter_id=METER_GUEST, bands=[band]))

    def _install_core_l2(self, dp):
        """Tabla 0, prio 10: la misma VLAN cruza de un troncal al otro."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        pairs = ((CORE_TRUNKS[0], CORE_TRUNKS[1]),
                 (CORE_TRUNKS[1], CORE_TRUNKS[0]))
        for vlan_id in VLANS:
            for in_port, out_port in pairs:
                match = parser.OFPMatch(
                    in_port=in_port, vlan_vid=vlan_id | ofp.OFPVID_PRESENT)
                self._add_flow(dp, PRIO_CORE_L2, match,
                               [parser.OFPActionOutput(out_port)])

    def _install_gateway_arp(self, dp):
        """Tabla 0, prio 300: ARP request por el gateway -> controlador.

        Se exige la VLAN correcta: solo se contesta el gateway de la propia
        VLAN. El orden de los campos importa (eth_type antes de arp_*)."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        to_controller = [parser.OFPActionOutput(
            ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        for vlan_id, gw_ip in GATEWAYS.items():
            match = parser.OFPMatch(
                vlan_vid=vlan_id | ofp.OFPVID_PRESENT,
                eth_type=ETH_P_ARP, arp_op=arp.ARP_REQUEST, arp_tpa=gw_ip)
            self._add_flow(dp, PRIO_GW_ARP, match, to_controller)

    def _install_gateway_icmp(self, dp):
        """Tabla 0, prio 250 (X2): echo request al gateway -> controlador.

        Solo se contesta el gateway de la VLAN en la que llego la trama, y
        solo si el paquete va dirigido a la MAC del gateway."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        to_controller = [parser.OFPActionOutput(
            ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        for vlan_id, gw_ip in GATEWAYS.items():
            match = parser.OFPMatch(
                vlan_vid=vlan_id | ofp.OFPVID_PRESENT, eth_type=ETH_P_IP,
                eth_dst=GW_MAC, ipv4_dst=gw_ip, ip_proto=IPPROTO_ICMP,
                icmpv4_type=icmp.ICMP_ECHO_REQUEST)
            self._add_flow(dp, PRIO_GW_ICMP, match, to_controller)

    def _install_gateway_entry(self, dp):
        """Tabla 0: lo dirigido a la MAC del gateway entra al ruteo."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        tagged = (ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT)  # cualquier VID
        match = parser.OFPMatch(
            vlan_vid=tagged, eth_type=ETH_P_IP, eth_dst=GW_MAC)
        self._add_flow(dp, PRIO_GW_IP, match, goto=TABLE_ACL)
        # Lo demas dirigido al gateway (no IPv4) no se reenvia: se descarta.
        self._add_flow(dp, PRIO_GW_DROP, parser.OFPMatch(eth_dst=GW_MAC))

    def _install_acl(self, dp):
        """Tabla 1: matriz de seguridad R4, proactiva y sin estado.

        Sin estado significa que cada sentido se evalua por separado: por
        eso Servidores -> Ventas permite de forma explicita las respuestas
        HTTP (TCP con puerto origen 80). Lo que no coincide con ningun
        permiso se descarta en el propio switch, sin consultar al
        controlador. El orden de los campos importa: eth_type antes de
        ipv4_*, e ip_proto antes de tcp_*."""
        parser = dp.ofproto_parser

        def acl_match(src, dst, l4=None):
            fields = dict(eth_type=ETH_P_IP,
                          ipv4_src=SUBNETS[src], ipv4_dst=SUBNETS[dst])
            if l4 == 'icmp':
                fields['ip_proto'] = IPPROTO_ICMP
            elif l4 is not None:
                kind, port = l4
                fields['ip_proto'] = IPPROTO_TCP
                fields[kind] = port
            return parser.OFPMatch(**fields)

        for src, dst, l4, meter in ACL_ALLOW:
            self._add_flow(dp, PRIO_ACL_ALLOW, acl_match(src, dst, l4),
                           table_id=TABLE_ACL, goto=TABLE_ROUTE, meter=meter)
        for src, dst in ACL_DENY:
            self._add_flow(dp, PRIO_ACL_DENY, acl_match(src, dst),
                           table_id=TABLE_ACL)
        self._add_flow(dp, PRIO_ACL_DEFAULT, parser.OFPMatch(),
                       table_id=TABLE_ACL)

    def _install_routes(self, dp):
        """Tabla 2: una regla por (host destino, puerto de entrada).

        Un switch no reenvia un paquete por el mismo puerto por el que
        entro, salvo que la accion sea OFPP_IN_PORT. Por eso la salida
        depende del puerto de entrada."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # Se exige trama etiquetada (cualquier VID). Open vSwitch rechaza
        # (OFPBAC_MATCH_INCONSISTENT) un set_field de vlan_vid cuando el
        # match no garantiza que ya hay una etiqueta que modificar.
        tagged = (ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT)
        for vlan_id, ip, mac, host_port in HOSTS.values():
            for in_port in CORE_TRUNKS:
                out_port = (ofp.OFPP_IN_PORT if in_port == host_port
                            else host_port)
                match = parser.OFPMatch(
                    in_port=in_port, vlan_vid=tagged,
                    eth_type=ETH_P_IP, ipv4_dst=ip)
                actions = [
                    parser.OFPActionDecNwTtl(),
                    parser.OFPActionSetField(eth_src=GW_MAC),
                    parser.OFPActionSetField(eth_dst=mac),
                    parser.OFPActionSetField(
                        vlan_vid=vlan_id | ofp.OFPVID_PRESENT),
                    parser.OFPActionOutput(out_port),
                ]
                self._add_flow(dp, PRIO_ROUTE, match, actions,
                               table_id=TABLE_ROUTE)

    # ------------------------------------------- errores de OpenFlow
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def on_error(self, ev):
        """Un switch rechazo un mensaje. Por defecto os-ken no lo muestra."""
        msg = ev.msg
        self.logger.warning(
            'Error OpenFlow en dpid=%s: tipo=%s codigo=%s '
            '(una regla fue rechazada)', msg.datapath.id, msg.type, msg.code)

    # ------------------------------------------------- ARP del gateway
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        if dp.id != DPID_CORE:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        tag = pkt.get_protocol(vlan.vlan)
        if eth is None or tag is None:
            return
        in_port = msg.match['in_port']
        # Solo se contesta el gateway de la VLAN en la que llego la trama.
        gw_ip = GATEWAYS.get(tag.vid)

        req = pkt.get_protocol(arp.arp)
        if req is not None:
            if req.opcode == arp.ARP_REQUEST and req.dst_ip == gw_ip:
                self._send_arp_reply(dp, in_port, tag.vid, req)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        echo = pkt.get_protocol(icmp.icmp)
        if (ip is not None and echo is not None
                and echo.type == icmp.ICMP_ECHO_REQUEST and ip.dst == gw_ip):
            self._send_echo_reply(dp, in_port, tag.vid, eth, ip, echo)

    def _send_arp_reply(self, dp, in_port, vid, req):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            dst=req.src_mac, src=GW_MAC,
            ethertype=ether_types.ETH_TYPE_8021Q))
        reply.add_protocol(vlan.vlan(
            vid=vid, ethertype=ether_types.ETH_TYPE_ARP))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=GW_MAC, src_ip=req.dst_ip,
            dst_mac=req.src_mac, dst_ip=req.src_ip))
        reply.serialize()

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data))

    def _send_echo_reply(self, dp, in_port, vid, eth, ip, echo):
        """X2: el gateway contesta el ping de los hosts de su propia VLAN."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            dst=eth.src, src=GW_MAC, ethertype=ether_types.ETH_TYPE_8021Q))
        reply.add_protocol(vlan.vlan(
            vid=vid, ethertype=ether_types.ETH_TYPE_IP))
        reply.add_protocol(ipv4.ipv4(
            src=ip.dst, dst=ip.src, proto=in_proto.IPPROTO_ICMP, ttl=64))
        reply.add_protocol(icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE,
            csum=0, data=echo.data))
        reply.serialize()

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data))

    # ---------------------------------------------------------- ayudas
    @staticmethod
    def _add_flow(dp, priority, match, actions=None, table_id=0, goto=None,
                  meter=None):
        """Sin acciones ni goto, la regla descarta. Orden de instrucciones
        segun la especificacion: meter, acciones, goto-table."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = []
        if meter is not None:
            inst.append(parser.OFPInstructionMeter(meter))
        if actions:
            inst.append(parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions))
        if goto is not None:
            inst.append(parser.OFPInstructionGotoTable(goto))
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=table_id, priority=priority,
            match=match, instructions=inst))

    @staticmethod
    def _clear_flows(dp):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=ofp.OFPTT_ALL,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch()))
        dp.send_msg(parser.OFPBarrierRequest(dp))

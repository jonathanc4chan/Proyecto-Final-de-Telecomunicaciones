# Campus SDN - Distribuidora Quetzal

Proyecto final de Telecomunicaciones I (Universidad Mariano Gálvez de Guatemala).
Autor: Jonathan Joel Chán Cuellar.

Red de campus con tres switches Open vSwitch, VLAN 802.1Q, ruteo inter-VLAN y
política de seguridad, todo definido por un controlador os-ken 3.1.1 que habla
OpenFlow 1.3. Incluye las extensiones X1 (red de invitados con límite de 2 Mbps)
y X2 (el gateway responde ping).

## Requisitos

- Ubuntu con Mininet, Open vSwitch y os-ken 3.1.1 (`osken-manager`).
- Si os-ken está en un entorno virtual, actívelo en la terminal del controlador
  (por ejemplo `source ~/sdn-env/bin/activate`).

## Levantar la red (dos comandos, dos terminales)

Ejecute ambos desde la carpeta del proyecto.

**Terminal 1 - controlador** (primero):

```
osken-manager --ofp-tcp-listen-port 6653 campus_controller.py
```

**Terminal 2 - topología** (cuando el controlador ya esté corriendo):

```
sudo python3 campus_topo.py
```

Para levantar también el host de invitados `h5` (VLAN 99, extensión X1):

```
sudo python3 campus_topo.py --with-h5
```

Aparece el prompt `mininet>`. En el controlador deben verse tres mensajes
`Switch conectado` (dpid 1, 2 y 3) y ninguna línea `Error OpenFlow`.

Para cerrar: `exit` en Mininet y `Ctrl+C` en el controlador. Si una sesión quedó
mal cerrada: `sudo mn -c`.

El script de topología solo crea nodos, enlaces y los servicios de `srv`; no
instala ninguna regla. Todas las reglas las instala el controlador cuando cada
switch se conecta.

## Comprobaciones rápidas en `mininet>`

| Comando | Resultado esperado |
|---|---|
| `h1 ping -c2 h2` | responde, `ttl=64` (misma VLAN, no se rutea) |
| `h1 ping -c2 srv` | responde, `ttl=63` (ruteado en s1) |
| `h1 ping -c2 h3` | sin respuesta (Ventas -> Contabilidad denegado) |
| `h1 curl -s http://10.0.30.10` | portal interno (puerto 80) |
| `h1 curl -s -m3 http://10.0.30.10:8080` | sin respuesta (Ventas solo HTTP/80) |
| `h3 curl -s http://10.0.30.10:8080` | panel de administración |
| `h1 ping -c2 10.0.10.1` | responde el gateway (X2) |
| `pingall` | 40 % perdido (12 de 20) sin h5; 60 % perdido (12 de 30) con h5 |
| `h5 curl -s http://10.0.30.10` | portal, a 2 Mbps como máximo (X1) |
| `h5 ping -c2 srv` | sin respuesta (invitados solo HTTP/80) |

Reglas instaladas (tras `pingall`): `sudo ovs-ofctl -O OpenFlow13 dump-flows s1`
(49 reglas), `s2` (6) y `s3` (6). Meters: `... dump-meters s1`.

## Robustez (R6)

Con la red levantada: borrar las reglas (`for s in s1 s2 s3; do sudo ovs-ofctl
-O OpenFlow13 del-flows $s; done`) deja la red sin tráfico; al reiniciar solo el
controlador (`Ctrl+C` y volver a ejecutar el comando de la terminal 1), los
switches se reconectan solos y el controlador reinstala todo. No hace falta
tocar Mininet.

## Diseño en breve

- **s2 y s3 (acceso):** puerto de acceso sin etiqueta -> se agrega 802.1Q y sale
  por el troncal (puerto 1); troncal -> se quita la etiqueta y sale solo a los
  puertos de esa VLAN. Lo demás se descarta (sin regla de table-miss).
- **s1 (núcleo), tres tablas:**
  - Tabla 0: ARP y ping al gateway van al controlador (reactivo); el IPv4
    dirigido a la MAC del gateway pasa a la tabla 1; el tráfico de la misma VLAN
    cruza de un troncal al otro sin ruteo.
  - Tabla 1: política de seguridad (R4 y X1), proactiva y sin estado, con
    denegación por defecto y meter de 2 Mbps para invitados.
  - Tabla 2: ruteo proactivo por host: TTL-1, MAC origen = gateway, MAC destino
    = host, VLAN del destino. Si el destino queda detrás del mismo troncal por
    el que llegó el paquete, sale con `IN_PORT` (caso "mismo switch de acceso").
- Al conectarse cada switch el controlador borra sus reglas (y los meters de s1)
  y reinstala todo, por eso la red se recupera sola.

## Restricciones del enunciado

No se usa la acción `NORMAL` ni las opciones `tag`/`trunks` de OVS; no hay
`ovs-ofctl add-flow` ni reglas en el script de topología; los hosts no hacen de
router ni tienen ARP estático; solo se usa os-ken 3.1.1.

## Limitación conocida

La ACL no guarda estado: Servidores -> Ventas permite TCP con puerto origen 80
(respuestas HTTP), pero un servidor comprometido podría enviar paquetes con ese
puerto origen. Un cortafuegos con estado (o el campo `tcp_flags` de versiones
posteriores de OpenFlow) lo evitaría.

## Archivos

- `campus_topo.py` - topología Mininet (con o sin `h5`) y servicios de `srv`.
- `campus_controller.py` - aplicación os-ken (VLAN, ruteo, ACL, X1, X2).

"""Distributed Bellman-Ford with full vectors and poisoned reverse.

Metrics at or above 16 mean unreachable, as permitted by the assignment.
Only callback arguments, Router.addr and Router.send supply network information.
"""
from json import dumps, loads
from packet import Packet
from router import Router


class DVrouter(Router):
    INFINITY = 16

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.adjacent = {}  # port -> (address, outgoing cost)
        self.received = {}  # port -> (sequence, full vector)
        self.routes = {}  # destination -> (distance, outgoing port)
        self.serial = 0

    def _recalculate(self):
        """Rebuild from current evidence, including cost increases/withdrawals."""
        result = {}
        for port, (neighbor, cost) in sorted(self.adjacent.items()):
            candidates = dict(self.received.get(port, (-1, {}))[1])
            candidates[neighbor] = 0
            for destination, advertised in candidates.items():
                distance = cost + advertised
                if destination == self.addr or distance >= self.INFINITY:
                    continue
                choice = (distance, port)
                if destination not in result or choice < result[destination]:
                    result[destination] = choice
        changed = result != self.routes
        self.routes = result
        return changed

    def _announce(self):
        self.serial += 1
        for port, (neighbor, _) in self.adjacent.items():
            vector = {self.addr: 0}
            for destination, (distance, exit_port) in self.routes.items():
                vector[destination] = self.INFINITY if exit_port == port else distance
            payload = dumps({'sequence': self.serial, 'vector': vector})
            self.send(port, Packet(Packet.ROUTING, self.addr, neighbor, payload))

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            route = self.routes.get(packet.dst_addr)
            if route is not None:
                self.send(route[1], packet)
            return
        if not packet.is_routing or port not in self.adjacent:
            return
        if packet.src_addr != self.adjacent[port][0]:
            return
        message = loads(packet.content)
        previous = self.received.get(port, (-1, {}))[0]
        if message['sequence'] <= previous:
            return
        self.received[port] = (message['sequence'], message['vector'])
        if self._recalculate():
            self._announce()

    def handle_new_link(self, port, endpoint, cost):
        self.adjacent[port] = (endpoint, cost)
        self.received.pop(port, None)
        self._recalculate()
        self._announce()

    def handle_remove_link(self, port):
        self.adjacent.pop(port, None)
        self.received.pop(port, None)
        self._recalculate()
        self._announce()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._announce()

    def __repr__(self):
        return f'DVrouter({self.addr!r}, routes={self.routes!r})'

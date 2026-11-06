"""Sequence-numbered link-state flooding and directed shortest paths."""
from heapq import heappop, heappush
from itertools import count
from json import dumps, loads
from packet import Packet
from router import Router


class LSrouter(Router):
    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.adjacent = {}
        self.database = {}  # origin -> (sequence, outgoing adjacency)
        self.serial = 0
        self.forwarding = {}

    def _send_record(self, port, origin):
        sequence, edges = self.database[origin]
        payload = dumps({'origin': origin, 'sequence': sequence, 'edges': edges})
        self.send(port, Packet(Packet.ROUTING, self.addr,
                               self.adjacent[port][0], payload))

    def _publish(self):
        edges = {}
        for neighbor, cost in self.adjacent.values():
            edges[neighbor] = min(cost, edges.get(neighbor, float('inf')))
        self.serial += 1
        self.database[self.addr] = (self.serial, edges)
        self._shortest_paths()
        for port in self.adjacent:
            self._send_record(port, self.addr)

    def _shortest_paths(self):
        """Carry the first local port through each Dijkstra relaxation.

        Edges are directed: reverse costs must come from the other router's LSA.
        Clients have no LSA and are naturally terminal vertices.
        """
        best = {}
        pending = []
        order = count()
        for port, (neighbor, cost) in self.adjacent.items():
            heappush(pending, (cost, port, next(order), neighbor))
        while pending:
            distance, first_port, _, vertex = heappop(pending)
            if vertex == self.addr:
                continue
            choice = (distance, first_port)
            if vertex in best and best[vertex] <= choice:
                continue
            best[vertex] = choice
            edges = self.database.get(vertex, (0, {}))[1]
            for target, weight in edges.items():
                candidate = (distance + weight, first_port)
                if target != self.addr and (target not in best or candidate < best[target]):
                    heappush(pending, (*candidate, next(order), target))
        self.forwarding = {vertex: choice[1] for vertex, choice in best.items()}

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            exit_port = self.forwarding.get(packet.dst_addr)
            if exit_port is not None:
                self.send(exit_port, packet)
            return
        if not packet.is_routing or port not in self.adjacent:
            return
        message = loads(packet.content)
        origin = message['origin']
        if origin == self.addr:
            return
        sequence = message['sequence']
        old_sequence, old_edges = self.database.get(origin, (-1, {}))
        if sequence <= old_sequence:
            return
        self.database[origin] = (sequence, message['edges'])
        if old_edges != message['edges']:
            self._shortest_paths()
        for other in self.adjacent:
            if other != port:
                self._send_record(other, origin)

    def handle_new_link(self, port, endpoint, cost):
        self.adjacent[port] = (endpoint, cost)
        self._publish()
        # Bring a newly attached neighbor up to date without waiting for heartbeats.
        for origin in self.database:
            if origin != self.addr:
                self._send_record(port, origin)

    def handle_remove_link(self, port):
        self.adjacent.pop(port, None)
        self._publish()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._publish()

    def __repr__(self):
        return f'LSrouter({self.addr!r}, forwarding={self.forwarding!r})'

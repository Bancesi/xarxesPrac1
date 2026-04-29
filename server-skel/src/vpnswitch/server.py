import socket
import struct
from loguru import logger

class VpnServer:
    def __init__(self, config):
        self.config = config
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Tabla MAC: guarda qué dirección IP/Puerto tiene cada MAC
        self.mac_table = {} 
        self.HEADER_SIZE = 11

    def run(self):
        # Escuchar en todas las IPs en el puerto configurado
        self.sock.bind(("0.0.0.0", self.config.port))
        logger.info(f"Servidor PIXES activo en el puerto {self.config.port}")

        while True:
            data, addr = self.sock.recvfrom(2048)
            
            if len(data) < self.HEADER_SIZE:
                continue

            # Desempaquetamos usando el formato del RFC: ! (network) B (1 byte) H (2 bytes) 8s (8 bytes)
            opcode, cid, payload = struct.unpack("!BH8s", data[:self.HEADER_SIZE])

            if opcode == 3:  # OP_TRAFFIC
                self.handle_traffic(data, addr)
            elif opcode == 1: # OP_REGISTER
                logger.debug(f"Registro recibido de CID: {cid} desde {addr}")
                # Aquí podrías añadir lógica de registro si quieres nota extra

    def handle_traffic(self, data, addr):
        eth_frame = data[self.HEADER_SIZE:]
        if len(eth_frame) < 14: return # Trama demasiado corta

        # En Ethernet: Destino es bytes 0-6, Origen es bytes 6-12
        dst_mac = eth_frame[0:6].hex(":")
        src_mac = eth_frame[6:12].hex(":")

        # Aprendizaje dinámico de MAC (Sección 8.1 del RFC)
        if src_mac not in self.mac_table:
            logger.info(f"Aprendida nueva MAC {src_mac} en dirección {addr}")
        self.mac_table[src_mac] = addr

        # Reenvío (Sección 8.2 del RFC)
        if dst_mac in self.mac_table:
            target_addr = self.mac_table[dst_mac]
            self.sock.sendto(data, target_addr)
        else:
            if self.config.unknown_mac == "flood":
                # Enviar a todos menos al que lo envió
                for mac, target_addr in self.mac_table.items():
                    if target_addr != addr:
                        self.sock.sendto(data, target_addr)
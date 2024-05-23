import socket
import platform
from colorama import init, Fore
from scapy.all import ARP, Ether, srp, sniff, IP, Ether
from tqdm import tqdm

init(autoreset=True)

header = f"""
{Fore.CYAN}
>>===============================================================<<
|| ____                    _                _                    ||
||/ ___|  __ _ _ __ ___   / \   _ __   __ _| |_   _ _______ _ __ ||
||\___ \ / _` | '__/ _ \ / _ \ | '_ \ / _` | | | | |_  / _ | '__|||
|| ___) | (_| | | |  __// ___ \| | | | (_| | | |_| |/ |  __| |   ||
|||____/ \__,_|_|  \___/_/   \_|_| |_|\__,_|_|\__, /___\___|_|   ||
||                                            |___/              ||
>>===============================================================<<
                                                       
{Fore.RESET}
{Fore.YELLOW}  ======= BIENVENIDO AL ANALIZADOR DE REDES =======
{Fore.RED}  =======          By Linoreki              =======
{Fore.RESET}
"""

def menu():
    while True:
        print(header)
        print(Fore.BLUE + "1. Analizador de puertos")
        print(Fore.GREEN + "2. Analizar paquetes")
        print(Fore.RED + "3. Hosts de la red")
        print(Fore.RED + "4. Salir")

        opcion = input(Fore.CYAN + "Ingrese una opción: ")

        if opcion == "1":
            inputs_puertos()
        elif opcion == "2":
            packet_callback_inputs()
        elif opcion == "3":
            Host_UP()
        elif opcion == "4":
            print(Fore.RED + "Saliendo del programa...")
            break
        else:
            print(Fore.RED + "Opción no válida. Por favor, elija una opción válida.")

def inputs_puertos():
    protocolo = input(Fore.BLUE + "Qué tipo de escaneo quieres realizar (TCP), (UDP) o TCP/UDP: ")
    target_host = input(Fore.BLUE + "Ingrese la dirección IP o nombre de host a escanear: ")
    start_port = int(input(Fore.BLUE + "Ingrese el puerto inicial del escaneo: "))
    end_port = int(input(Fore.BLUE + "Ingrese el puerto final del escaneo: "))
    time = float(input(Fore.BLUE + "Establezca el tiempo de timeout entre puertos: "))

    if protocolo.upper() == "TCP":
        scan_ports(target_host, start_port, end_port, time, tcp=True, udp=False)
    elif protocolo.upper() == "UDP":
        scan_ports(target_host, start_port, end_port, time, tcp=False, udp=True)
    elif protocolo.upper() == "TCP/UDP":
        scan_ports(target_host, start_port, end_port, time, tcp=True, udp=True)
    else:
        print(Fore.RED + "Protocolo no válido. Por favor, elija TCP, UDP o TCP/UDP.")

def scan_ports(target, start_port, end_port, time, tcp=True, udp=True):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(Fore.RED + f"No se pudo resolver el nombre del host: {e}")
        return

    if start_port > end_port:
        print(Fore.RED + "El puerto inicial no puede ser mayor que el puerto final.")
        return

    print(Fore.GREEN + f"Escaneando puertos en {target_ip} ...")

    tcp_open_ports = []
    udp_open_ports = []

    ports = range(start_port, end_port + 1)

    if tcp:
        print(Fore.BLUE + "Escaneando puertos TCP:")
        for port in tqdm(ports, desc="TCP", unit="port"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(time)
            try:
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    tcp_open_ports.append(port)
            except Exception as e:
                pass
            finally:
                sock.close()
        print(Fore.GREEN + "\nPuertos TCP abiertos:")
        for port in tcp_open_ports:
            print(Fore.GREEN + f"TCP Puerto {port}: Abierto")       

    if udp:
        print(Fore.BLUE + "Escaneando puertos UDP:")
        for port in tqdm(ports, desc="UDP", unit="port"):
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(time)
            try:
                udp_sock.sendto(b'', (target_ip, port))
                data, addr = udp_sock.recvfrom(1024)
                udp_open_ports.append(port)
            except socket.timeout:
                pass
            except ConnectionResetError as e:
                if e.winerror == 10054:
                    continue
            except Exception as e:
                pass
            finally:
                udp_sock.close()


        print(Fore.GREEN + "\nPuertos UDP abiertos:")
        for port in udp_open_ports:
            print(Fore.GREEN + f"UDP Puerto {port}: Abierto")

    input("Presione Enter para continuar...")

def packet_callback_inputs():
    iface = input(Fore.BLUE + "Ingrese la interfaz de red a escuchar (ej. eth0): ")
    print(f"Escuchando paquetes en la interfaz {iface} ...")

    try:
        sniff(iface=iface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n\nCaptura de paquetes detenida.")
    except Exception as e:
        print(Fore.RED + f"Error al capturar paquetes: {e}")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst

        log_line = f"Paquete capturado - IP: {ip_src} -> {ip_dst}, MAC: {mac_src} -> {mac_dst}\n"

        print(log_line)

        filename = "Packet_Output.txt"

        save_ip_to_file(log_line, filename)

def save_ip_to_file(log_line, filename):
    try:
        with open(filename, "a") as file:
            file.write(log_line)
    except Exception as e:
        print(f"Error al guardar paquetes: {e}")

def Host_UP():
    target_ip = input(Fore.BLUE + "Ingrese el rango de IP a escanear (ej. 192.168.1.0/24): ")
    print(Fore.GREEN + f"Escaneando la red {target_ip} ...")

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print(Fore.GREEN + "Dispositivos encontrados en la red:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    input("Presione Enter para continuar...")

if __name__ == "__main__":
    menu()

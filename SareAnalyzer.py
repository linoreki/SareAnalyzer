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
{Fore.YELLOW}  ======= WELCOME TO THE NETWORK ANALYZER =======
{Fore.RED}  =======          By Linoreki              =======
{Fore.RESET}
"""

def menu():
    while True:
        print(header)
        print(Fore.BLUE + "1. Port Analyzer")
        print(Fore.GREEN + "2. Analyze Packets")
        print(Fore.RED + "3. Network Hosts")
        print(Fore.RED + "4. Exit")

        option = input(Fore.CYAN + "Enter an option: ")

        if option == "1":
            port_inputs()
        elif option == "2":
            packet_callback_inputs()
        elif option == "3":
            host_up()
        elif option == "4":
            print(Fore.RED + "Exiting the program...")
            break
        else:
            print(Fore.RED + "Invalid option. Please choose a valid option.")

def port_inputs():
    protocol = input(Fore.BLUE + "What type of scan do you want to perform (TCP), (UDP), or TCP/UDP: ")
    target_host = input(Fore.BLUE + "Enter the IP address or hostname to scan: ")
    start_port = int(input(Fore.BLUE + "Enter the start port for the scan: "))
    end_port = int(input(Fore.BLUE + "Enter the end port for the scan: "))
    timeout = float(input(Fore.BLUE + "Set the timeout between ports: "))

    if protocol.upper() == "TCP":
        scan_ports(target_host, start_port, end_port, timeout, tcp=True, udp=False)
    elif protocol.upper() == "UDP":
        scan_ports(target_host, start_port, end_port, timeout, tcp=False, udp=True)
    elif protocol.upper() == "TCP/UDP":
        scan_ports(target_host, start_port, end_port, timeout, tcp=True, udp=True)
    else:
        print(Fore.RED + "Invalid protocol. Please choose TCP, UDP, or TCP/UDP.")

def scan_ports(target, start_port, end_port, timeout, tcp=True, udp=True):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(Fore.RED + f"Could not resolve hostname: {e}")
        return

    if start_port > end_port:
        print(Fore.RED + "Start port cannot be greater than end port.")
        return

    print(Fore.GREEN + f"Scanning ports on {target_ip} ...")

    tcp_open_ports = []
    udp_open_ports = []

    ports = range(start_port, end_port + 1)

    if tcp:
        print(Fore.BLUE + "Scanning TCP ports:")
        for port in tqdm(ports, desc="TCP", unit="port"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    tcp_open_ports.append(port)
            except Exception as e:
                pass
            finally:
                sock.close()
        print(Fore.GREEN + "\nOpen TCP ports:")
        for port in tcp_open_ports:
            print(Fore.GREEN + f"TCP Port {port}: Open")       

    if udp:
        print(Fore.BLUE + "Scanning UDP ports:")
        for port in tqdm(ports, desc="UDP", unit="port"):
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(timeout)
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


        print(Fore.GREEN + "\nOpen UDP ports:")
        for port in udp_open_ports:
            print(Fore.GREEN + f"UDP Port {port}: Open")

    input("Press Enter to continue...")

def packet_callback_inputs():
    iface = input(Fore.BLUE + "Enter the network interface to listen on (e.g., eth0): ")
    print(f"Listening for packets on interface {iface} ...")

    try:
        sniff(iface=iface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n\nPacket capture stopped.")
    except Exception as e:
        print(Fore.RED + f"Error capturing packets: {e}")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst

        log_line = f"Packet captured - IP: {ip_src} -> {ip_dst}, MAC: {mac_src} -> {mac_dst}\n"

        print(log_line)

        filename = "Packet_Output.txt"

        save_ip_to_file(log_line, filename)

def save_ip_to_file(log_line, filename):
    try:
        with open(filename, "a") as file:
            file.write(log_line)
    except Exception as e:
        print(f"Error saving packets: {e}")

def host_up():
    target_ip = input(Fore.BLUE + "Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    print(Fore.GREEN + f"Scanning network {target_ip} ...")

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print(Fore.GREEN + "Devices found on the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    input("Press Enter to continue...")

if __name__ == "__main__":
    menu()

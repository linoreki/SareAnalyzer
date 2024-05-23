# SareAnalyzer

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![Scapy Version](https://img.shields.io/badge/scapy-latest-orange.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey.svg)

## Descripción

**SareAnalyzer** es una herramienta de análisis de redes escrita en Python que permite realizar escaneos de puertos, captura de paquetes y detección de hosts en la red. Esta herramienta está diseñada para ayudar a los administradores de red y a los entusiastas de la seguridad a comprender mejor su infraestructura de red.

## Características

- **Escaneo de puertos TCP y UDP**: Realiza un escaneo de puertos para identificar servicios abiertos en un host específico.
- **Captura de paquetes**: Escucha y captura tráfico de red en una interfaz específica.
- **Detección de hosts**: Identifica dispositivos activos en la red local utilizando ARP.

## Instalación

### Prerrequisitos

- Python 3.x
- `pip` (gestor de paquetes de Python)

### Instalación del repositorio:

   ```sh
   git clone https://github.com/tuusuario/SareAnalyzer.git
   cd SareAnalyzer
   ````
### Instala las dependencias necesarias:

  ```sh
  pip install -r requirements.txt
   ````
### Dependencias adicionales para Windows

Para los usuarios de Windows, se recomienda instalar Npcap para la captura de paquetes. Puedes descargar Npcap desde [aquí](https://npcap.org).


## Uso:
Para iniciar la herramienta, simplemente ejecuta el archivo `SareAnalyzer.py`:

  ```sh
  python SareAnalyzer.py


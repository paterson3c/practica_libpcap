
'''
    ethmsg.py
    Implementación del protocolo de mensajeria basica para emision de mensajes en tiempo real sobre ethernet.
    Autor: Manuel Ruiz <manuel.ruiz.fernandez@uam.es>
    2024 EPS-UAM
'''

from ethernet import *
from arp import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

ETHTYPE = 0x3003
#Dirección de difusión (Broadcast)
broadcast = bytes([0xFF]*6)




def process_ethMsg_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_EthMsg_frame
        Descripción: Esta función procesa las tramas mensajes sobre ethernet. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype ETHTYPE (si ha sido registrada en initEth). 
                - Imprimir el contenido de los datos indicando la direccion MAC del remitente, la dirección IP de destino (en notación decimal a.b.c.d), asi como el tiempo de recepcion del mensaje, según el siguiente formato:
					[<segundos.microsegundos>] <MAC> -> <IP>: <mensaje> 
                - En caso de que no exista retornar
            
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ethMsg
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    if data is None:
        return
    
    message = f"[{header.ts.tv_sec}.{header.ts.tv_usec}] {srcMac} -> {data[0:4]}: {data[4:]}"
    print(f"{message}\n")
    return



def initEthMsg(interface:str) -> int:
    '''
        Nombre: initEthMsg
        Descripción: Esta función construirá inicializará el nivel ethMsg. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_ethMsg_frame con el Ethertype ETHTYPE
        Argumentos:   
			interfaz
    '''
    registerEthCallback(process_ethMsg_frame, ETHTYPE)
    
    return 0

def sendEthMsg(ip:int, message:bytes) -> bytes:
    '''
        Nombre: sendEthMsg
        Descripción: Esta función mandara un mensaje en broacast 
            
            Esta función debe realizar, al menos, las siguientes tareas:
                - Crear una trama Ehernet con el mensaje remitido
                - Enviar un mensaje en broadcast
		Argumentos:
			ip: Direccion IP a la que remitir el mensaje. Enviar como una palabra de 32 bits en orden de red.
			message: datos con el mensaje a remitir.
                
        Retorno: 
			Numero de Bytes transmitidos en el mensaje.
			None en caso de que no haya podido emitir el mensaje
    '''
    # Crear la trama Ethernet
    package = ip.to_bytes(4, 'big') + message # Ip destino + mensaje
    
    #mac = ARPResolution(ip)
    
    #if mac is None:
    #    return None
    
    #if sendEthernetFrame(package, len(package), ETHTYPE, mac) == -1: # Enviar la trama Ethernet
    #    return None
    
    if sendEthernetFrame(package, len(package), ETHTYPE, broadcast) == -1: # Enviar la trama Ethernet
        return None
    
    return len(package)
    

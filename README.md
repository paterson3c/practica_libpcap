# Práctica ARP con libpcap y Python

Este proyecto implementa una herramienta en Python para la captura, envío y análisis de tráfico ARP sobre redes Ethernet, utilizando `libpcap` y validada en Mininet.

## 🧪 Criterios de evaluación (todos realizados)
- Captura y análisis de tramas Ethernet
- Envío y recepción de peticiones/respuestas ARP
- Manejo de ARP gratuito
- Gestión de caché ARP con sincronización mediante locks
- Impresión de mensajes sobre protocolo 0x3003
- Validación con sentencias `debug` y capturas documentadas en `memoria.pdf`

## 🔧 Tecnologías
- Python 3
- libpcap
- Mininet

## ▶️ Ejecución
1. Iniciar red virtual:
```bash
sudo mn --nat
```
2. Abrir terminales para nodos:
```bash
gterm h1
gterm h2
```
3. Ejecutar el script:
```bash
sudo python3 practica2.py <--itf> <--debug>
```

## 📌 Notas
El archivo `memoria.pdf` explica detalladamente el funcionamiento interno del código y documenta todas las pruebas de ejecución.

## 👥 Autores
- Miguel Jesús Paterson González – [GitHub](https://github.com/paterson3c)
- Mijaíl Sazhin Martín – [GitHub](https://github.com/MijailSM)

[Repositorio en GitHub](https://github.com/paterson3c/practica_libpcap)

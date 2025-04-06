Autores: Miguel Jesús Paterson González y Mijaíl Sazhin Martín

Se ha añadido un archivo memoria.pdf que desglosa el código y contiene pruebas de ejecución para validar los criterios de evaluación

CRITERIOS DE EVALUACIÓN:

Normativa de entrega cumplida en su totalidad: REALIZADO
Fichero leeme.txt bien explicado: REALIZADO
Recibir tramas Ethernet, realizar comprobaciones y llamar correctamente a la función de callback de nivel superior REALIZADO
Enviar tramas Ethernet  correctamente REALIZADO
Imprimir mensajes sobre el protocolo 0x3003 REALIZADO
Enviar correctamente peticiones ARP REALIZADO
Procesar correctamente peticiones ARP recibidas REALIZADO
Enviar correctamente respuestas ARP REALIZADO
Procesar correctamente respuestas ARP REALIZADO
Manejo correcto de la caché ARP REALIZADO
Uso correcto de Locks REALIZADO
Realiza correctamente el ARP Gratuito REALIZADO

Para validar los criterios de evaluación se han incluido sentencias debug en los ficheros y en la memoria se han añadido capturas con pruebas de ello


EJECUCIÓN:

Para poder ejecutar la práctica en la carpeta /src se ejecutará lo siguiente para iniciar la red:

```bash
sudo mn --nat
```

Para generar las terminales de los nodos h1 y h2 se ejecutará lo siguiente:

```bash
gterm h1
gterm h2
```

Dentro de las nuevas terminales se ejecutará la práctica de esta manera:

```bash
sudo python3 practica2.py <--itf (interfaz)> <--debug>
```

Para ayuda para el uso del programa dentro de la consola de practica2.py introduce lo siguiente:

```bash
> h
```
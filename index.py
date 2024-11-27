import tkinter as tk
from tkinter import filedialog
import threading
from scapy.all import sniff, IP, TCP, UDP

# Variable para controlar la captura
capture = False
packet_count = 0  # Contador de paquetes

# Función que captura los paquetes en segundo plano
def packet_callback(packet):
    global packet_count
    packet_count += 1  # Incrementar el número de paquete

    # Extraer información del paquete
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Otro"

        # Formatear la información en columnas
        packet_info = f"{packet_count:<10}{src_ip:<20}{dst_ip:<20}{protocol:<10}\n"

        # Insertar el texto en la interfaz
        text_box.insert(tk.END, packet_info)
        text_box.see(tk.END)

# Función para iniciar la captura de paquetes
def start_sniffing():
    global capture
    capture = True
    sniff(prn=packet_callback, stop_filter=lambda x: not capture, store=False)

# Función para detener la captura
def stop_sniffing():
    global capture
    capture = False

# Función para ejecutar la captura en un hilo separado
def start_sniffing_thread():
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True  # Permite que el hilo se cierre cuando se cierra la aplicación
    sniff_thread.start()

# Función para borrar el contenido de la captura
def clear_capture():
    global packet_count
    text_box.delete(1.0, tk.END)  # Borra todo el contenido del Text widget
    packet_count = 0  # Reinicia el contador de paquetes

# Función para guardar el contenido en un archivo de texto
def save_capture():
    # Abrir un diálogo para seleccionar la ubicación del archivo
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    
    if file_path:
        try:
            # Abrir el archivo y escribir el contenido del text_box
            with open(file_path, "w") as f:
                f.write(text_box.get(1.0, tk.END))  # Escribe el contenido del Text widget en el archivo
        except Exception as e:
            print(f"Error al guardar el archivo: {e}")

# Crear la ventana principal
root = tk.Tk()
root.title("Capturador de Paquetes de Red")

# Crear un Frame para el área de texto y la barra de desplazamiento
text_frame = tk.Frame(root)
text_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Crear un widget de texto para mostrar los paquetes capturados
text_box = tk.Text(text_frame, height=20, width=80)
text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Crear una barra de desplazamiento y conectarlo al Text widget
scrollbar = tk.Scrollbar(text_frame, command=text_box.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
text_box.config(yscrollcommand=scrollbar.set)

# Insertar la cabecera de la tabla
text_box.insert(tk.END, f"{'Num':<10}{'Origen':<20}{'Destino':<20}{'Protocolo':<10}\n")
text_box.insert(tk.END, "-"*60 + "\n")

# Crear un marco para contener todos los botones en una línea
button_frame = tk.Frame(root)
button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

# Crear los botones para "Borrar" y "Guardar" alineados a la izquierda
clear_button = tk.Button(button_frame, text="Borrar", command=clear_capture)
clear_button.pack(side=tk.LEFT, padx=5)

save_button = tk.Button(button_frame, text="Guardar", command=save_capture)
save_button.pack(side=tk.LEFT, padx=5)

# Crear un marco interno para alinear los botones "Iniciar" y "Detener" a la derecha
right_button_frame = tk.Frame(button_frame)
right_button_frame.pack(side=tk.RIGHT)

# Crear un botón para iniciar la captura
start_button = tk.Button(right_button_frame, text="Iniciar captura", command=start_sniffing_thread)
start_button.pack(side=tk.LEFT, padx=5)

# Crear un botón para detener la captura
stop_button = tk.Button(right_button_frame, text="Detener captura", command=stop_sniffing)
stop_button.pack(side=tk.LEFT, padx=5)

# Iniciar el bucle de la interfaz gráfica
root.mainloop()

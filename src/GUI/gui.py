import tkinter as tk
from tkinter import scrolledtext

root = tk.Tk()
root.title("Sniffer GUI")

# Ajouter un bouton pour démarrer le sniffer
start_button = tk.Button(root, text="Start Sniffer", command=sniffer.start_sniffer)

start_button.pack(pady=10)

# Ajouter un bouton pour arrêter le sniffer
stop_button = tk.Button(root, text="Stop Sniffer", command=stop_sniffer)
stop_button.pack(pady=10)

# Ajouter une zone de texte défilante pour afficher les paquets capturés
text_area = scrolledtext.ScrolledText(root, width=100, height=20)
text_area.pack(pady=10)

# Démarrer la boucle principale de l'application
root.mainloop()
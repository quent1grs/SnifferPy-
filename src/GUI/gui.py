import scapy.all as scapy
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
import os
import stat
import datetime

# Variables globales pour compter les protocoles
TCPcount = 0
UDPcount = 0
ARPcount = 0
ICMPcount = 0
ICMPv6count = 0
DNScount = 0
unknowncount = 0
IPv4count = 0
IPv6count = 0

# Dossier de sauvegarde
SAVE_DIR = "save"

# Fonction pour déterminer le nom du protocole
def get_protocol_name(packet):
    if packet.haslayer(scapy.TCP):
        return "TCP"
    elif packet.haslayer(scapy.UDP):
        return "UDP"
    elif packet.haslayer(scapy.ARP):
        return "ARP"
    elif packet.haslayer(scapy.ICMP):
        return "ICMP"
    elif packet.haslayer(scapy.ICMPv6EchoRequest) or packet.haslayer(scapy.ICMPv6EchoReply):
        return "ICMPv6"
    elif packet.haslayer(scapy.DNS):
        return "DNS"
    else:
        return "Unknown"

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Sniffeur de Paquets Réseau")

        # Liste des interfaces disponibles
        self.interfaces = scapy.get_if_list()

        # Choix de l'interface réseau
        self.interface_label = tk.Label(master, text="Interface Réseau :")
        self.interface_label.pack()

        self.interface_combo = ttk.Combobox(master, values=self.interfaces)
        self.interface_combo.pack()

        # Choix du nombre de paquets
        self.packet_count_label = tk.Label(master, text="Nombre de paquets à capturer :")
        self.packet_count_label.pack()

        self.packet_count_entry = tk.Entry(master)
        self.packet_count_entry.insert(0, "20")  # Valeur par défaut
        self.packet_count_entry.pack()

        # Checkbox pour sauvegarder ou non
        self.save_var = tk.BooleanVar()
        self.save_checkbox = tk.Checkbutton(master, text="Enregistrer la capture dans un fichier", variable=self.save_var)
        self.save_checkbox.pack()

        # Bouton démarrer la capture
        self.start_button = tk.Button(master, text="Démarrer la Capture", command=self.start_sniffer)
        self.start_button.pack()

        # Bouton arrêter la capture
        self.stop_button = tk.Button(master, text="Arrêter la Capture", command=self.stop_sniffer, state=tk.DISABLED)
        self.stop_button.pack()

        # Zone d'affichage des résultats
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=100, height=30)
        self.output_text.pack()

        # Drapeau pour indiquer si la capture doit être arrêtée
        self.stop_flag = threading.Event()

    def start_sniffer(self):
        interface = self.interface_combo.get()
        packet_count = self.packet_count_entry.get()

        if not interface:
            self.output_text.insert(tk.END, "Veuillez choisir une interface réseau.\n")
            return

        if not packet_count.isdigit():
            self.output_text.insert(tk.END, "Veuillez entrer un nombre valide de paquets.\n")
            return

        if self.save_var.get():
            # Si besoin de sauvegarder : créer le dossier 'save' s'il n'existe pas
            if not os.path.exists(SAVE_DIR):
                os.makedirs(SAVE_DIR)

            # Générer un nom de fichier unique avec un horodatage
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.save_file = os.path.join(SAVE_DIR, f"capture_resultats_{timestamp}.txt")

            # Vider le fichier au début de la capture
            with open(self.save_file, "w") as f:
                f.write("Début de la capture...\n\n")

            # Changer les permissions du fichier pour permettre à tous les utilisateurs de le supprimer
            os.chmod(self.save_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)

        self.output_text.delete(1.0, tk.END)
        self.stop_flag.clear()  # Réinitialiser le drapeau
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.sniff_packets, args=(interface, int(packet_count)), daemon=True).start()

    def stop_sniffer(self):
        self.stop_flag.set()  # Définir le drapeau pour arrêter la capture
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, interface, packet_count):
        try:
            scapy.sniff(iface=interface, prn=self.print_info, stop_filter=lambda x: self.stop_flag.is_set(), count=packet_count)
            resume = f"""
Capture terminée.
TCP: {TCPcount} | UDP: {UDPcount} | ARP: {ARPcount} | ICMP: {ICMPcount} | ICMPv6: {ICMPv6count} | DNS: {DNScount} | Inconnus: {unknowncount}
IPv4: {IPv4count} | IPv6: {IPv6count}
"""
            self.output_text.insert(tk.END, resume)
            self.output_text.see(tk.END)

            if self.save_var.get():
                with open(self.save_file, "a") as f:
                    f.write("\n" + resume)

        except Exception as e:
            self.output_text.insert(tk.END, f"Erreur: {e}\n")
            self.output_text.see(tk.END)
        finally:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def print_info(self, packet):
        global TCPcount, UDPcount, ARPcount, ICMPcount, ICMPv6count, DNScount, unknowncount, IPv4count, IPv6count

        try:
            protocol = get_protocol_name(packet)
            info = f"Protocole: {protocol}\n"

            # Détection IPv4 ou IPv6
            if packet.haslayer(scapy.IP):
                info += "Protocole IP : IPv4\n"
                info += f"IP Source: {packet[scapy.IP].src}\n"
                info += f"IP Destination: {packet[scapy.IP].dst}\n"
                IPv4count += 1

            elif packet.haslayer(scapy.IPv6):
                info += "Protocole IP : IPv6\n"
                info += f"IP Source: {packet[scapy.IPv6].src}\n"
                info += f"IP Destination: {packet[scapy.IPv6].dst}\n"
                IPv6count += 1

            if packet.haslayer(scapy.TCP):
                info += f"Port Source: {packet[scapy.TCP].sport}\n"
                info += f"Port Destination: {packet[scapy.TCP].dport}\n"
                TCPcount += 1

            if packet.haslayer(scapy.UDP):
                info += f"Port Source: {packet[scapy.UDP].sport}\n"
                info += f"Port Destination: {packet[scapy.UDP].dport}\n"
                UDPcount += 1

            if packet.haslayer(scapy.ICMP):
                ICMPcount += 1

            if packet.haslayer(scapy.ICMPv6EchoRequest) or packet.haslayer(scapy.ICMPv6EchoReply):
                ICMPv6count += 1

            if packet.haslayer(scapy.ARP):
                ARPcount += 1

            if packet.haslayer(scapy.DNS):
                DNScount += 1

            if protocol == "Unknown":
                unknowncount += 1

            info += f"Résumé: {packet.summary()}\n"
            info += "-"*50 + "\n"

            # Affichage à l'écran
            self.output_text.insert(tk.END, info)
            self.output_text.see(tk.END)

            # Sauvegarde dans le fichier si demandé
            if self.save_var.get():
                with open(self.save_file, "a") as f:
                    f.write(info)

        except Exception as e:
            self.output_text.insert(tk.END, f"Erreur: {e}\n")
            self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

import socket
import platform
import time
import tkinter as tk
from tkinter import ttk
import threading
import re
import winreg
import getpass


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Client BRMTIT")

        # Стиль для кнопок и других виджетов
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Helvetica', 12), padding=5)
        self.style.configure('TEntry', font=('Helvetica', 12))
        self.style.configure('TLabel', font=('Helvetica', 12))

        # Поле ввода для IP адреса сервера
        self.ip_label = ttk.Label(root, text="IP адрес сервера:")
        self.ip_label.pack(pady=5)
        self.ip_entry = ttk.Entry(root)
        self.ip_entry.pack()

        # Поле ввода для порта сервера
        self.port_label = ttk.Label(root, text="Порт сервера:")
        self.port_label.pack(pady=5)
        self.port_entry = ttk.Entry(root)
        self.port_entry.pack()

        # Кнопка для подключения к серверу
        self.connect_button = ttk.Button(root, text="Подключиться к серверу", command=self.connect_to_server)
        self.connect_button.pack(pady=5)

        # Кнопка для отключения от сервера
        self.disconnect_button = ttk.Button(root, text="Отключиться от сервера", command=self.disconnect_from_server,
                                            state=tk.DISABLED)
        self.disconnect_button.pack(pady=5)

        # Кнопка для очистки логов
        self.clear_button = ttk.Button(root, text="Очистить логи", command=self.clear_logs, state=tk.DISABLED)
        self.clear_button.pack(pady=5)

        # Текстовое поле для отображения логов
        self.text_area = tk.Text(root, width=50, height=15, font=('Helvetica', 12))
        self.text_area.pack(padx=10, pady=10)

        # Метка с информацией о состоянии подключения
        self.connection_status_label = ttk.Label(root, text="Состояние: Не подключено", font=('Helvetica', 12), foreground="red")
        self.connection_status_label.pack(pady=5)

        # Метка с информацией о создателе
        self.credit_label = ttk.Label(root, text="Выполнила команда БРМТИТ", font=('Helvetica', 10))
        self.credit_label.pack(side=tk.BOTTOM, pady=10)

        # Сокет клиента
        self.client_socket = None
        self.connected = False
        self.keep_alive_thread = None

    def connect_to_server(self):
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        threading.Thread(target=self.connect_and_receive, args=(ip, port)).start()

    def connect_and_receive(self, ip, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.client_socket.connect((ip, port))
            self.log_message("Подключение к серверу установлено.")
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)
            self.connection_status_label.config(text="Состояние: Подключено", foreground="green")

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            product_name = winreg.QueryValueEx(key, "ProductName")[0]
            version_name = re.search(r"Windows \d+", product_name).group()

            def username_get():
                try:
                    key2 = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion', 0, winreg.KEY_READ)
                    username, _ = winreg.QueryValueEx(key2, 'RegisteredOwner')
                    return username
                except FileNotFoundError:
                    return getpass.getuser()  # Если не удалось получить имя из реестра, возвращаем имя текущего пользователя

            usernames = username_get()
            version_name = version_name.replace("Windows ", "Windows: ")
            self.log_message(f"{version_name}:{usernames}")
            client_send = f"{version_name}: {usernames}"
            self.client_socket.sendall(client_send.encode())

            response = self.client_socket.recv(1024).decode()
            self.log_message(f"Ответ от сервера: {response}")
            self.connected = True
            self.start_keep_alive()

        except Exception as e:
            self.log_message(f"Ошибка подключения к серверу: {e}")
            self.disconnect_from_server()

    def disconnect_from_server(self):
        if self.client_socket:
            self.client_socket.close()
        self.log_message("Отключено от сервера.")
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.NORMAL)
        self.connected = False
        self.connection_status_label.config(text="Состояние: Не подключено", foreground="red")
        if self.keep_alive_thread:
            self.keep_alive_thread.cancel()
            self.keep_alive_thread = None

    def clear_logs(self):
        self.text_area.delete('1.0', tk.END)
        self.clear_button.config(state=tk.DISABLED)

    def log_message(self, message):
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)

    def start_keep_alive(self):
        self.keep_alive_thread = threading.Thread(target=self.keep_alive)
        self.keep_alive_thread.start()

    def keep_alive(self):
        while self.connected:
            try:
                self.client_socket.sendall(bytes("Keep Alive", "utf-8"))
                time.sleep(1)  # Отправлять запрос каждые 5 секунд
            except Exception as e:
                self.disconnect_from_server()
                break


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()

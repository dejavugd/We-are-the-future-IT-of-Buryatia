import socket
import tkinter as tk
from tkinter import ttk
import threading
import re


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Серверная часть")

        # Styling
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Helvetica', 12), padding=5)
        self.style.configure('TEntry', font=('Helvetica', 12))
        self.style.configure('TLabel', font=('Helvetica', 12))

        # Main Frame
        self.main_frame = ttk.Frame(root, padding=10)
        self.main_frame.pack()

        # Header
        self.header_label = ttk.Label(self.main_frame, text="Server", font=('Helvetica', 16, 'bold'))
        self.header_label.grid(row=0, column=0, columnspan=2, pady=10)

        # Port
        self.port_label = ttk.Label(self.main_frame, text="Порт сервера:", font=('Helvetica', 12), width=14)
        self.port_label.grid(row=1, column=0, pady=5, sticky=tk.W)
        self.port_entry = ttk.Combobox(self.main_frame, font=('Helvetica', 12), values=["8080", "1111", "8888", "1313"], width=14)
        self.port_entry.grid(row=1, column=1, pady=5, sticky=tk.EW)

        # User Name
        self.user_label = ttk.Label(self.main_frame, text="Имя пользователя:", font=('Helvetica', 12))
        self.user_label.grid(row=2, column=0, pady=5, sticky=tk.W)
        self.user_entry = ttk.Entry(self.main_frame, font=('Helvetica', 12), width=14)
        self.user_entry.grid(row=2, column=1, pady=5, sticky=tk.EW)

        # Version
        self.version_label = ttk.Label(self.main_frame, text="Минимальная версия OC:", font=('Helvetica', 12))
        self.version_label.grid(row=3, column=0, pady=5, sticky=tk.W)
        self.version_combobox = ttk.Combobox(self.main_frame, font=('Helvetica', 12), values=["7", "8", "8.1", "10", "11"], width=14)
        self.version_combobox.grid(row=3, column=1, pady=5, sticky=tk.EW)

        # Buttons
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        self.start_button = ttk.Button(self.button_frame, text="Запустить сервер", command=self.start_server)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(self.button_frame, text="Остановить сервер", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)

        self.clear_button = ttk.Button(self.button_frame, text="Очистить логи", command=self.clear_logs)
        self.clear_button.grid(row=0, column=2, padx=5)

        self.new_win_button = ttk.Button(self.button_frame, text="Запрещенные прог.", command=self.open_win)
        self.new_win_button.grid(row=0, column=3, padx=5)
        # В метод __init__ класса ServerGUI добавляем кнопку "Подключенные пользователи"
        self.connected_users_button = ttk.Button(self.button_frame, text="Подключенные пользователи", command=self.show_connected_users)
        self.connected_users_button.grid(row=0, column=4, padx=5)

        # Text Area
        self.text_area = tk.Text(self.main_frame, width=90, height=15, font=('Helvetica', 12))
        self.text_area.grid(row=5, column=0, columnspan=4, padx=10, pady=10)

        # Status Label
        self.status_label = ttk.Label(self.main_frame, text="Сервер не запущен", font=('Helvetica', 12), foreground="red")
        self.status_label.grid(row=6, column=0, columnspan=2, pady=10)

        # Credits Label
        self.credit_label = ttk.Label(root, text="Выполнила команда БРМТИТ", font=('Helvetica', 10))
        self.credit_label.pack(side=tk.BOTTOM, pady=10)

        self.server_running = False
        self.client_connections = {}

    def disconnect_user(self, address):
        try:
            client_socket = self.client_connections[address]
            client_socket.close()
            del self.client_connections[address]
            self.log_message(f"Пользователь {address} отключен от сервера")
        except Exception as e:
            self.log_message(f"Ошибка при отключении пользователя {address}: {e}")

    def show_connected_users(self):
        self.connected_users_window = tk.Toplevel(self.root)
        self.connected_users_window.title("Подключенные пользователи")

        connected_users_frame = ttk.Frame(self.connected_users_window, padding=10)
        connected_users_frame.pack()

        ttk.Label(connected_users_frame, text="Подключенные пользователи:", font=('Helvetica', 12)).pack()

        # Обновление списка подключенных пользователей
        connected_users = list(self.client_connections.keys())
        for address in connected_users:
            user_frame = ttk.Frame(connected_users_frame)
            user_frame.pack(fill=tk.X)

            ttk.Label(user_frame, text=str(address), font=('Helvetica', 12)).pack(side=tk.LEFT, padx=5)

            disconnect_button = ttk.Button(user_frame, text="Отключить",
                                           command=lambda addr=address: self.disconnect_user(addr))
            disconnect_button.pack(side=tk.RIGHT, padx=5)

        self.disconnect_all_button = ttk.Button(connected_users_frame, text="Отключить всех пользователей", command=self.disconnect_all_users)
        self.disconnect_all_button.pack(pady=10)


    def disconnect_all_users(self):
        for address, client_socket in self.client_connections.items():
            client_socket.close()
        self.client_connections.clear()
        self.log_message("Все пользователи отключены от сервера")

    def update_server_status_label(self, is_running):
        if is_running:
            self.status_label.config(text="Сервер запущен", foreground="green")
        else:
            self.status_label.config(text="Сервер не запущен", foreground="red")

    def start_server(self):
        port = int(self.port_entry.get())

        self.server_running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))
        self.server_socket.bind(('', port))
        self.server_socket.listen(1)
        self.log_message(f"Сервер запущен.\nIP:{temp_socket.getsockname()[0]} PORT:{port}\nОжидание подключений...")
        self.update_server_status_label(True)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.NORMAL)
        threading.Thread(target=self.accept_connections).start()

    def stop_server(self):
        self.server_running = False
        self.server_socket.close()
        self.log_message("Сервер остановлен")
        self.update_server_status_label(False)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.NORMAL)

    def accept_connections(self):
        while self.server_running:
            try:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()
            except Exception as e:
                if self.server_running:
                    self.log_message(f"Ошибка при подключении клиента: {e}")

    def handle_client(self, client_socket, client_address):
        try:
            self.log_message(f"Подключение установлено с {client_address}")

            # Отправка списка правил клиенту
            with open("rules.txt", "r") as file:
                rules_text = f'ПРАВИЛА, Минимальная версия OC - {self.version_combobox.get()}, Разрешенные пользователи - {self.user_entry.get()}, Запрещенные программы - {file.read()}'
                client_socket.sendall(bytes(rules_text, 'utf-8'))

            self.client_connections[client_address] = client_socket
        except Exception as e:
            self.log_message(f"Ошибка при обработке клиента {client_address}: {e}")

    def log_message(self, message):
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)

    def clear_logs(self):
        self.text_area.delete('1.0', tk.END)
        self.clear_button.config(state=tk.DISABLED)

    def open_win(self):
        New_win = tk.Toplevel(self.root)
        New_win.geometry("450x150")
        New_win.resizable(False, False)
        New_win.protocol("WM_DELETE_WINDOW", lambda: None)
        NewWin(New_win)


class NewWin:
    def __init__(self, root):
        self.root = root
        self.root.title("ЗАПРЕТ")

        # Main Frame
        self.main_frame = ttk.Frame(root, padding=10)
        self.main_frame.pack()

        # Header Label
        self.header_label = ttk.Label(self.main_frame, text="Запрет программ", font=('Helvetica', 16, 'bold'))
        self.header_label.grid(row=0, column=0, columnspan=2, pady=10)

        # Text Entry
        self.text_entry_label = ttk.Label(self.main_frame, text="Введите текст:")
        self.text_entry_label.grid(row=1, column=0, sticky=tk.W)

        self.text_entry = ttk.Entry(self.main_frame, width=50)
        self.text_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Buttons
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=2, column=0, columnspan=2, pady=10)

        self.save_button = ttk.Button(self.button_frame, text="Сохранить", command=self.save_to_file)
        self.save_button.grid(row=0, column=0, padx=5)

        self.close_button = ttk.Button(self.button_frame, text="Назад", command=self.close_window)
        self.close_button.grid(row=0, column=1, padx=5)

    def save_to_file(self):
        text = self.text_entry.get()
        with open("rules.txt", "w") as file:
            file.write(text)
        print("Текст сохранён")

    def close_window(self):
        self.save_to_file()
        self.root.destroy()


def extract_ip_port(message):
    ip_port_regex = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,5})'
    match = re.search(ip_port_regex, message)
    if match:
        ip = match.group(1)
        port = match.group(2)
        return ip, port
    else:
        return None, None


if __name__ == "__main__":
    with open("rules.txt", "w") as file:
        file.write("")
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()

import socket
import datetime
import tkinter as tk
from tkinter import ttk
from packaging import version
import threading


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Server BRMTIT")

        # Стиль для кнопок
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Helvetica', 12), padding=5)

        # Надпись "Сервер не запущен"
        self.label = tk.Label(root, text="Сервер не запущен", font=('Helvetica', 14, 'bold'), fg="red")
        self.label.pack(pady=10)

        # Надпись "Выполнила команда БРМТИТ"
        self.credit_label = tk.Label(root, text="Выполнила команда БРМТИТ", font=('Helvetica', 10))
        self.credit_label.pack(side=tk.BOTTOM, pady=10)

        # Добавление элементов для ввода порта
        self.port_label = tk.Label(root, text="Порт:", font=('Helvetica', 12))
        self.port_label.pack()
        self.port_entry = tk.Entry(root, font=('Helvetica', 12))
        self.port_entry.pack()

        # Добавляем выпадающий список для выбора версии Windows
        self.version_label = tk.Label(root, text="Минимальная версия Windows:", font=('Helvetica', 12))
        self.version_label.pack()
        self.version_combobox = ttk.Combobox(root, font=('Helvetica', 12), values=["7", "8", "8.1", "10", "11"])
        self.version_combobox.pack()

        # Кнопки и текстовое поле как в вашем примере
        self.start_button = ttk.Button(root, text="Запустить сервер", command=self.start_server)
        self.start_button.pack(pady=5)

        self.stop_button = ttk.Button(root, text="Остановить сервер", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.clear_button = ttk.Button(root, text="Очистить логи", command=self.clear_logs)
        self.clear_button.pack(pady=5)

        self.text_area = tk.Text(root, width=50, height=15, font=('Helvetica', 12))
        self.text_area.pack(padx=10, pady=10)

        self.server_running = False
        self.client_connections = {}  # Словарь для хранения соединений с клиентами

    def update_server_status_label(self, is_running):
        if is_running:
            self.label.config(text="Сервер запущен", fg="green")
        else:
            self.label.config(text="Сервер не запущен", fg="red")

    def start_server(self):
        port = int(self.port_entry.get())

        self.server_running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))
        self.server_socket.bind(('', port))
        self.server_socket.listen(1)
        self.log_message(f"Сервер запущен.\nIP:{temp_socket.getsockname()[0]} PORT:{port}\nОжидание подключений...")
        self.update_server_status_label(True)  # Обновляем надпись о статусе сервера
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.NORMAL)
        threading.Thread(target=self.accept_connections).start()

    def stop_server(self):
        self.server_running = False
        self.server_socket.close()
        self.log_message("Сервер остановлен")
        self.update_server_status_label(False)  # Обновляем надпись о статусе сервера
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
            client_ip, client_port = client_address

            client_os = client_socket.recv(1024).decode() # Получаем информацию о версии ОС клиента
            client_name = client_os.split(": ")[0]
            client_version = client_os.split(": ")[1]
            self.log_message(f"Операционная система клиента - {client_name}:{client_version}")

            selected_version = self.version_combobox.get()  # Получаем выбранную версию Windows

            if client_name.startswith("Windows"):
                self.log_message(f"Версия Windows клиента: {client_version}, Выбранная версия: {selected_version}")
                if version.parse(client_version) >= version.parse(selected_version):
                    client_socket.sendall(bytes(f'Вы используете Windows версии {selected_version} или выше.', 'utf-8'))
                else:
                    client_socket.sendall(
                        bytes(f'Вы используете Windows версии ниже {selected_version}. Доступ к серверу закрыт!',
                              'utf-8'))
                    client_socket.close()
            else:
                client_socket.sendall(bytes('Этот сервер поддерживает только Windows.', 'utf-8'))

            # Сохраняем ссылку на соединение с клиентом
            self.client_connections[client_address] = client_socket
        except Exception as e:
            self.log_message(f"Ошибка при обработке клиента {client_address}: {e}")

    def respond_to_last_request(self, client_address, response):
        try:
            client_socket = self.client_connections.get(client_address)
            if client_socket:
                client_socket.sendall(response.encode())
        except Exception as e:
            self.log_message(f"Ошибка при отправке ответа клиенту {client_address}: {e}")

    def log_message(self, message):
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)

    def clear_logs(self):
        self.text_area.delete('1.0', tk.END)
        self.clear_button.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()

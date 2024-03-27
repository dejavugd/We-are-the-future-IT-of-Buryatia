import psutil
import getpass
import socket
import threading
import tkinter as tk
from tkinter import ttk
import winreg
import time
import re

check_name = ["правила", "rules"]
min_version = ["OC", "Минимальная", "Версия"]
user_white_list = ["Имя"]


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Клиенская часть")

        # Стиль для кнопок и других виджетов
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Helvetica', 12), padding=5)
        self.style.configure('TEntry', font=('Helvetica', 12))
        self.style.configure('TLabel', font=('Helvetica', 12))

        # Главный фрейм
        self.main_frame = ttk.Frame(root, padding=10)
        self.main_frame.pack()

        # Header
        self.header_label = ttk.Label(self.main_frame, text="Client", font=('Helvetica', 16, 'bold'))
        self.header_label.grid(row=0, column=0, columnspan=4, pady=10)

        # Метка для IP адреса сервера
        self.ip_label = ttk.Label(self.main_frame, text="IP адрес сервера:")
        self.ip_label.grid(row=1, column=0, pady=5, sticky=tk.W)

        # Поле ввода для IP адреса сервера
        self.ip_entry = ttk.Entry(self.main_frame, font=('Helvetica', 12))
        self.ip_entry.grid(row=1, column=1, pady=5, sticky=tk.EW)

        # Метка для порта сервера
        self.port_label = ttk.Label(self.main_frame, text="Порт сервера:")
        self.port_label.grid(row=2, column=0, pady=5, sticky=tk.W)

        # Поле ввода для порта сервера
        self.port_entry = ttk.Entry(self.main_frame, font=('Helvetica', 12))
        self.port_entry.grid(row=2, column=1, pady=5, sticky=tk.EW)

        # Кнопка для подключения к серверу
        self.connect_button = ttk.Button(self.main_frame, text="Подключиться к серверу", command=self.connect_to_server)
        self.connect_button.grid(row=3, column=0, columnspan=1, pady=10, sticky=tk.EW)

        # Кнопка для отключения от сервера
        self.disconnect_button = ttk.Button(self.main_frame, text="Отключиться от сервера",
                                            command=self.disconnect_from_server, state=tk.DISABLED)
        self.disconnect_button.grid(row=3, column=1, columnspan=1, pady=5, sticky=tk.EW)

        # Кнопка для очистки логов
        self.clear_button = ttk.Button(self.main_frame, text="Очистить логи", command=self.clear_logs,
                                       state=tk.DISABLED)
        self.clear_button.grid(row=3, column=2, columnspan=1, pady=5, sticky=tk.EW)

        # Пустая метка для разделения
        self.empty_label = ttk.Label(self.main_frame, text="", font=('Helvetica', 12))
        self.empty_label.grid(row=5, column=0, columnspan=2, pady=16)

        # Текстовое поле для отображения логов
        self.text_area = tk.Text(self.main_frame, width=75, height=15, font=('Helvetica', 12))
        self.text_area.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

        # Метка с информацией о состоянии подключения
        self.connection_status_label = ttk.Label(self.main_frame, text="Состояние: Не подключено", font=('Helvetica', 12), foreground="red")
        self.connection_status_label.grid(row=7, column=0, columnspan=3, pady=10)

        # Метка с информацией о создателе
        self.credit_label = ttk.Label(root, text="Выполнила команда БРМТИТ", font=('Helvetica', 10))
        self.credit_label.pack(side=tk.BOTTOM, pady=10, anchor="center")

        # Сокет клиента
        self.client_socket = None
        self.connected = False
        self.keep_alive_thread = None
        self.keep_alive_flag = threading.Event()
        self.keep_alive_flag.set()

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

            response = self.receive_data()
            self.log_message(f"Ответ от сервера: {response}")
            self.connected = True
            self.start_keep_alive()

        except Exception as e:
            self.log_message(f"Ошибка подключения к серверу: {e}")
            self.disconnect_from_server()

    def send_data(self, data):
        self.client_socket.sendall(data.encode())

    def receive_data(self):
        return self.client_socket.recv(1024).decode()

    def disconnect_from_server(self):
        if self.client_socket:
            self.client_socket.close()
        self.keep_alive_flag.clear()
        self.log_message("Отключено от сервера.")
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED)
        self.connected = False
        self.connection_status_label.config(text="Состояние: Не подключено", foreground="red")
        if self.keep_alive_thread and self.keep_alive_thread.is_alive():
            self.keep_alive_thread.join()
        self.keep_alive_thread = None

    def clear_logs(self):
        self.text_area.delete('1.0', tk.END)
        self.clear_button.config(state=tk.DISABLED)

    def log_message(self, message):
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)

        if "правила" in message.lower():
            self.check_rules(message)

    def start_keep_alive(self):
        self.keep_alive_thread = threading.Thread(target=self.keep_alive)
        self.keep_alive_thread.start()

    def keep_alive(self):
        while self.connected and self.keep_alive_flag.is_set():
            try:
                self.client_socket.sendall(bytes("Keep Alive", "utf-8"))
                time.sleep(1)
            except Exception as e:
                self.disconnect_from_server()
                break

    def check_rules(self, rules_text):
        print("Текст правил:", rules_text)
        rules_list = rules_text.split(", ")
        min = (rules_list[1].split("- "))[1]
        white_list = (rules_list[2].split("- "))[1]
        block_proc = (rules_list[3].split("- "))[1]
        b = get_windows_version()
        print(b)
        print(min, "\n", white_list, "\n", block_proc)
        if min <= b:
            print("Версия Windows соответствует требованиям!")
            if check_username_in_list(white_list, getpass.getuser()):
                if white_list == "":
                    print("Правило, связанное с пользователями, не активно!")
                    active_program = check_active_programs(block_proc)
                    if not active_program:
                        if block_proc == "":
                            print("Правило, связанное с блокировкой приложения, не активно!")
                            self.client_socket.sendall("ОТЧЕТ ПРОВЕРКИ\nВсе правила выполнены!".encode("utf-8"))
                            check_process_power()
                        else:
                            print("Приложение не активно!")
                            self.client_socket.sendall("ОТЧЕТ ПРОВЕРКИ\nВсе правила выполнены!".encode("utf-8"))
                            check_process_power()
                    else:
                        print("Приложение активно!")
                        self.client_socket.sendall(
                            "ОТЧЕТ ПРОВЕРКИ\nВерсия Windows соответствует требованиям!\nИмя пользователя есть в списках!\nОбнаружена запрещенная программа!".encode("utf-8"))
                        time.sleep(1)
                        self.disconnect_from_server()
                else:
                    print("Ваш пользователь есть в списках!")
                    active_program = check_active_programs(block_proc)
                    if not active_program:
                        if block_proc == "":
                            print("Правило, связанное с блокировкой приложения, не активно!")
                            self.client_socket.sendall("ОТЧЕТ ПРОВЕРКИ\nВсе правила выполнены!".encode("utf-8"))
                            check_process_power()
                        else:
                            print("Приложение не активно!")
                            self.client_socket.sendall("ОТЧЕТ ПРОВЕРКИ\nВсе правила выполнены!".encode("utf-8"))
                            check_process_power()
                    else:
                        print("Приложение активно!")
                        self.client_socket.sendall("ОТЧЕТ ПРОВЕРКИ\nВерсия Windows соответствует требованиям!\nИмя пользователя есть в списках!\nОбнаружена запрещенная программа!".encode("utf-8"))
                        time.sleep(1)
                        self.disconnect_from_server()
            else:
                print("Вам отказано в доступе к серверу!")
                self.client_socket.sendall("ОТЧЕТ ПРОВЕРКИ\nВерсия Windows соответствует требованиям!\nИмя пользователя отсутствует в списках!".encode("utf-8"))
                time.sleep(1)
                self.disconnect_from_server()
        else:
            print("Версия Windows не соответствует требованиям!")
            self.disconnect_from_server()
            time.sleep(1)


def check_active_programs(active_programs):
    with open('rules.txt', 'w') as f:
        f.write(active_programs)
    running_programs = [proc.info['name'].lower() for proc in psutil.process_iter(['name'])]
    active_check = active_programs.split()

    print("Активные программы для проверки:", active_check)

    for active_program in active_check:
        print("Проверяем программу:", active_program)
        if active_program.lower() in running_programs:
            return True

    return False


def check_process_power():
    while True:
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent >= 15:
            ClientGUI.disconnect_from_server()
            with open('rules.txt', 'r') as f:
                check_active_programs(f.read())
        time.sleep(10)


def check_username_in_list(white_list, user):
    if white_list == "":
        return user
    else:
        return user in white_list


def get_windows_version():
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    product_name = winreg.QueryValueEx(key, "ProductName")[0]
    version_name = re.search(r"Windows \d+", product_name).group()
    version = version_name.split(" ")[1]
    return version


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()

Список команды:
1) Семенюк Андрей Александрович (Капитан) https://t.me/dejavuGD
2) Коковин Владислав Сергеевич
3) Демочко Данил Владимирович
4) Коробко Ирина Николаевна
5) Буянтуев Тамир Максимович

Учебное заведение:
Государственное автономное профессиональное образовательное учреждение Республики Бурятия «Бурятский республиканский многопрофильный техникум инновационных технологий»

Требования к системе:
ОС Windows 10/11
(Тестирование на других ОС не проводились)

Инструкция по запуску сервера:
Запуск сервера:
1. Из папки distr запускаем server.exe
2. Указываем порт подключения (любой)
3. Выбираем из списка "Минимальную версию Windows" для подключения к серверу
4. Нажимаем "Запустить сервер"

Запуск клиента:
1. Из папки distr запускаем client.exe
2. В строку "IP адрес сервера" вводим IP сервера (IP можно посмотреть в окне запущенного сервера)
3. Указываем порт (который указали на сервере)
4. Нажимаем "Подключиться к серверу"

Использование системы:
При подключении клиента к серверу, происходит проверка минимальной версии windows у клиента. Версия windows у клиента определяется автоматически и сверяется с заданной на сервере. Если версия windows у клиента соответствует или выше указанной на сервере, сервер оставляет клиента подключенным к себе. Если версия windows у клиента ниже установленной, соединение автоматически разрывается. Для удобства реализована кнопка "Очистить логи". Так же в папке с сервером автоматически создается файл log.txt со всеми подключениями (кнопка "Очистить логи" на него не распространяется).
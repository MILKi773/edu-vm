# Описание
edu-vm — учебная виртуальная машина с двумя интерфейсами (веб-интерфейс и графический GUI) и набором модулей для работы с упрощённым ассемблером и интерпретатором. Ассемблерный язык УВМ описывается в формате YAML.

Ключевые свойства:
* Веб-интерфейс (Flask) для демонстрации работы VM в браузере
* Графический интерфейс (PySide6)
* Модули для ассемблера и интерпретатора: `assembler.py`, `interpretator.py`.
* Makefile для основных рабочий сценариев

Формат программы

```yaml
program:
  - cmd: <COMMAND_NAME>
    <operand1>: <value>
    <operand2>: <value>

```

Таблица инструкций

| Команда      | Операнды            | Описание                                    |
| ------------ | ------------------- | ------------------------------------------- |
| `LOAD_CONST` | `reg`, `value`      | Загрузка константы в регистр                |
| `READ_MEM`   | `reg`, `addr`       | Чтение значения из памяти в регистр         |
| `WRITE_MEM`  | `offset`, `src_reg` | Запись значения из регистра в память        |
| `BIN_OP`       | `reg`, `addr`       | Вычисление целочисленного квадратного корня |

# Описание модулей
* `app.py`: Flask-точка входа для веб-версии:
* `web/`: модули веб-логики
* `templates/index.html` и `static/style.css`: Фронтенд страницы: форма для ввода ассемблерного кода, кнопки для сборки/запуска, область вывода логов/регистров.
* `assembler.py`: Парсер ассемблера и компоновщик в байт-код виртуальной машины.
* `interpretator.py`: Исполнитель машинного / промежуточного кода
* `gui_backend.py`: Мост между GUI и ядром (assembler/interpretator)
* `utils.py`: Вспомогательные функции

# Настройки и переменные Makefile / окружения

Makefile содержит ключевые переменные:

* POETRY — команда poetry (по умолчанию poetry).

* PY, FLASK — вспомогательные наборы команд.

* SCRIPT — ожидаемый главный скрипт (main.py). Примечание: для корректной работы Makefile в репозитории должен присутствовать main.py или внести корректировку SCRIPT := app.py.

* HOST — адрес (по умолчанию 0.0.0.0).

* PORT — порт (по умолчанию 5000).

* GUNICORN_WORKERS — число рабочих процессов gunicorn.

* IMAGE — имя Docker image для сборки.

Основные команды Makefile:

* install — установка зависимостей (poetry install).

* install-pip — создание requirements.txt и установка через pip (Windows PowerShell команды).

* run-web — запускает веб-версию приложения (poetry run python main.py -m web согласно Makefile).

* run-gui — запускает GUI (poetry run python main.py -m gui).

* export-requirements — экспорт requirements.txt из poetry.

* clean — очистка временных файлов.

# Сборка проекта

Установка
```bash
# Установка зависимости (рекомендуется)
# Требуется установленный poetry
git clone https://github.com/eternal-git-dev/edu-vm.git
cd edu-vm

make install
# или вручную
poetry install
```
Запуск веб-версии
```bash
make run-web
```
Запуск GUI
```bash
make run-gui
```
Экспорт requirements.txt
```bash
make export-requirements
```
Очистка артефактов
```bash
make clean
```

# Примеры использования
Веб-интерфейс — главная страница

<img width="1796" height="950" alt="web" src="https://github.com/user-attachments/assets/209addbf-e910-4a5a-b724-ac8a179bf6a9" />


GUI — окно исполнения

<img width="1006" height="733" alt="gui" src="https://github.com/user-attachments/assets/ed33b48b-461a-4da3-b6cc-c21533df5095" />


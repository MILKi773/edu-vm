POETRY := poetry
PY := $(POETRY) run python
FLASK := $(POETRY) run flask
SCRIPT := main.py

RUN := $(POETRY) run python $(SCRIPT)

HOST := 0.0.0.0
PORT := 5000
GUNICORN_WORKERS := 4
IMAGE := myflaskapp:latest

.PHONY: help install shell run dev serve gunicorn test lint format build publish \
        export-requirements docker-build docker-run clean

help:
	@echo "Makefile targets:"
	@echo "  make install                # Установка зависимостей (poetry install)"
	@echo "  make install-pip            # Установка зависимостей через pip"
	@echo "  make run-web                # Запуск веб-версию приложения"
	@echo "  make run-gui                # Запуск приложения "
	@echo "  make export-requirements    # Экспортировать requirements.txt из poetry"
	@echo "  make clean                  # Очистить"

install:
	$(POETRY) install

install-pip:
	echo "pyside6>=6.10.1,<7.0.0" > requirements.txt
	echo "Flask>=3.0.0" >> requirements.txt
	echo "PyYAML>=6.0.3" >> requirements.txt
	python -m pip install --upgrade pip
	pip install -r requirements.txt


run-web:
	$(RUN) -m web

run-gui:
	$(RUN) -m gui

export-requirements:
	$(POETRY) export -f requirements.txt --output requirements.txt --without-hashes || \
		{ echo "If using an older poetry version, install 'poetry-plugin-export' or upgrade poetry."; exit 1; }


clean:
	@echo "Cleaning .pyc, __pycache__, build/ dist/ and .pytest_cache"
	find . -type d -name "__pycache__" -prune -exec rm -rf {} + || true
	find . -type f -name "*.pyc" -delete || true
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache || true
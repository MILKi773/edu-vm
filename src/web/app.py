import io
import traceback
from flask import Flask, render_template, request, jsonify, send_file
import yaml

from src.assembler import to_ir, assemble
from src.interpreter import run_program, parse_range

app = Flask(__name__)


@app.route('/')
def index():
    """Главная страница с редактором"""
    return render_template('index.html')


@app.route('/api/assemble_run', methods=['POST'])
def api_assemble_run():
    """API для ассемблирования и выполнения программы"""
    try:
        data = request.json

        # Получаем параметры
        yaml_text = data.get('yaml', '')
        mem_size = int(data.get('mem_size', 65536))
        regs_count = int(data.get('regs_count', 32))
        dump_range_text = data.get('dump_range', '0-220')

        # Парсим YAML
        data_yaml = yaml.safe_load(yaml_text)
        if not isinstance(data_yaml, dict) or 'program' not in data_yaml:
            return jsonify({
                'success': False,
                'error': 'YAML must contain top-level "program" list'
            })

        prog = data_yaml['program']

        # Конвертируем в IR
        ir = to_ir(prog)

        # Ассемблируем в бинарный вид
        binary = assemble(ir)

        # Сохраняем бинарник во временный файл
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
            f.write(binary)
            temp_bin_path = f.name

        # Парсим диапазон дампа
        dump_range = parse_range(dump_range_text)
        start, end = dump_range

        # Создаем временный CSV файл для дампа
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            temp_csv_path = f.name

        try:
            # Выполняем программу
            state = run_program(
                temp_bin_path,
                data_mem_size=mem_size,
                regs_count=regs_count,
                dump_csv=temp_csv_path,
                dump_range=dump_range
            )

            # Читаем результат дампа
            import csv
            mem_dump = []
            with open(temp_csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    mem_dump.append({
                        'address': int(row['address']),
                        'value': int(row['value'])
                    })

            # Формируем ответ
            response = {
                'success': True,
                'ir': ir,
                'binary_size': len(binary),
                'binary_hex': binary.hex(),
                'mem_dump': mem_dump,
                'registers': state['regs'],
                'log': f"Assembled {len(binary)} bytes, executed successfully."
            }

            return jsonify(response)

        finally:
            # Удаляем временные файлы
            try:
                os.unlink(temp_bin_path)
                os.unlink(temp_csv_path)
            except:
                pass

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })


@app.route('/api/download_binary', methods=['POST'])
def api_download_binary():
    """API для скачивания бинарного файла"""
    try:
        data = request.json
        yaml_text = data.get('yaml', '')

        data_yaml = yaml.safe_load(yaml_text)
        if not isinstance(data_yaml, dict) or 'program' not in data_yaml:
            return jsonify({'success': False, 'error': 'Invalid YAML'})

        prog = data_yaml['program']
        ir = to_ir(prog)
        binary = assemble(ir)

        # Возвращаем бинарный файл
        return send_file(
            io.BytesIO(binary),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='program.bin'
        )

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/save_yaml', methods=['POST'])
def api_save_yaml():
    """API для сохранения YAML в файл"""
    try:
        data = request.json
        yaml_text = data.get('yaml', '')
        filename = data.get('filename', 'program.yaml')

        # Проверяем расширение
        if not filename.endswith(('.yaml', '.yml')):
            filename += '.yaml'

        return send_file(
            io.BytesIO(yaml_text.encode('utf-8')),
            mimetype='text/yaml',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/example/<example_name>')
def api_example(example_name):
    """API для получения примеров программ"""
    examples = {
        'simple': """program:
  - cmd: LOAD_CONST
    reg: 0
    value: 123
  - cmd: WRITE_MEM
    addr: 100
    src_reg: 0
  - cmd: READ_MEM
    addr: 100
    reg: 1
""",
        'sqrt': """program:
  - cmd: LOAD_CONST
    reg: 0
    value: 100
  - cmd: LOAD_CONST
    reg: 1
    value: 25
  - cmd: WRITE_MEM
    addr: 200
    src_reg: 0
  - cmd: WRITE_MEM
    addr: 201
    src_reg: 1
  - cmd: BIN_OP
    result_addr: 202
    op1_addr: 200
    op2_addr: 201
""",
        'memory_ops': """program:
  - cmd: LOAD_CONST
    reg: 0
    value: 1000
  - cmd: LOAD_CONST
    reg: 1
    value: 42
  - cmd: WRITE_MEM
    addr: 150
    src_reg: 0
  - cmd: WRITE_MEM
    addr: 151
    src_reg: 1
  - cmd: READ_MEM
    addr: 150
    reg: 2
  - cmd: READ_MEM
    addr: 151
    reg: 3
"""
    }

    if example_name in examples:
        return jsonify({'success': True, 'yaml': examples[example_name]})
    else:
        return jsonify({'success': False, 'error': 'Example not found'})


def start():
    app.run(debug=True, host='0.0.0.0', port=5000)
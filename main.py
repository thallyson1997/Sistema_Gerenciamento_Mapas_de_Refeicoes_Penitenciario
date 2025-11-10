from flask import Flask, request, jsonify, render_template, session, flash, redirect, url_for
import os
import json
import re
from datetime import datetime
from functions.utils import (
    cadastrar_novo_usuario,
    validar_cadastro_no_usuario,
    validar_cpf,
    validar_email,
    validar_telefone,
    validar_matricula,
    validar_userna,
    validar_senha,
)

app = Flask(__name__)
app.secret_key = 'sgmrp_seap_2025_secret_key_desenvolvimento'
app.config['DEBUG'] = True

@app.route('/')
def index():
    #Página inicial
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    #Página de login
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    #Página de cadastro
    if request.method == 'POST':
        # coleta dados do formulário (se houver) e chama a função de cadastro
        form_data = request.form.to_dict()
        cadastrar_novo_usuario(form_data)
        # comportamento inicial: manter a página de cadastro após envio
        return render_template('cadastro.html')

    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    return jsonify({'ok': True})

@app.route('/dashboard')
def dashboard():
    return jsonify({'ok': True})


@app.route('/lotes')
def lotes():
    return jsonify({'ok': True})


@app.route('/lote/<int:lote_id>')
def lote_detalhes(lote_id):
    return jsonify({'ok': True})


@app.route('/admin/usuarios')
def admin_usuarios():
    return jsonify({'ok': True})


@app.route('/admin/usuarios/<int:user_id>/aprovar', methods=['POST'])
def aprovar_usuario(user_id):
    return jsonify({'ok': True})


@app.route('/admin/usuarios/<int:user_id>/revogar', methods=['POST'])
def revogar_usuario(user_id):
    return jsonify({'ok': True})


@app.route('/api/adicionar-dados', methods=['POST'])
def api_adicionar_dados():
    return jsonify({'ok': True})


@app.route('/api/excluir-dados', methods=['DELETE'])
def api_excluir_dados():
    return jsonify({'ok': True})


@app.route('/api/entrada-manual', methods=['POST'])
def api_entrada_manual():
    return jsonify({'ok': True})


@app.route('/api/adicionar-siisp', methods=['POST'])
def api_adicionar_siisp():
    return jsonify({'ok': True})


@app.route('/api/validar-campo', methods=['POST'])
def api_validar_campo():
    """Endpoint simples para validação de campos em tempo real.
    Retorna JSON: { 'valido': True, 'mensagem': 'OK' } por enquanto.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        campo = data.get('campo')
        valor = data.get('valor')
        # Se o cliente enviar o formulário completo como { form: { ... } },
        # delegamos para validar_cadastro_no_usuario (somente valida, não salva).
        form = data.get('form')
        if isinstance(form, dict):
            result = validar_cadastro_no_usuario(form)
            return jsonify(result), 200

        # Se receber um par campo/valor, despacha para o validador correspondente
        if campo and valor is not None:
            campo = campo.lower()
            if campo == 'cpf':
                res = validar_cpf(valor)
                if isinstance(res, dict):
                    res['campo'] = 'cpf'
                return jsonify(res), 200
            if campo == 'email':
                res = validar_email(valor)
                if isinstance(res, dict):
                    res['campo'] = 'email'
                return jsonify(res), 200
            if campo == 'telefone':
                res = validar_telefone(valor)
                if isinstance(res, dict):
                    res['campo'] = 'telefone'
                return jsonify(res), 200
            if campo == 'matricula':
                res = validar_matricula(valor)
                if isinstance(res, dict):
                    res['campo'] = 'matricula'
                return jsonify(res), 200
            if campo == 'usuario':
                res = validar_userna(valor)
                if isinstance(res, dict):
                    res['campo'] = 'usuario'
                return jsonify(res), 200
            if campo == 'senha':
                res = {'valido': True, 'mensagem': 'OK', 'campo': 'senha'}
                return jsonify(res), 200

        # Implementação padrão: responder OK (inclui campo quando informado)
        default_res = {'valido': True, 'mensagem': 'OK'}
        if campo:
            default_res['campo'] = campo
        return jsonify(default_res), 200
    except Exception:
        return jsonify({'valido': False, 'mensagem': 'Erro interno'}), 500


@app.route('/api/lotes')
def api_lotes():
    return jsonify({'ok': True})


@app.route('/api/novo-lote', methods=['POST'])
def api_novo_lote():
    return jsonify({'ok': True})

@app.route('/exportar-tabela')
def exportar_tabela():
    return jsonify({'ok': True})

@app.template_filter('data_br')
def filtro_data_br(data_str):
    try:
        return data_str
    except Exception:
        return data_str


@app.template_filter('status_badge')
def filtro_status_badge(status):
    return 'secondary'


@app.context_processor
def contexto_global():
    return {
        'app_nome': 'SGMRP',
        'app_versao': 'stub',
        'ano_atual': datetime.now().year,
        'usuario_logado': False,
        'usuario_nome': '',
    }


@app.errorhandler(404)
def pagina_nao_encontrada(error):
    return jsonify({'error': 'not found'}), 404


@app.errorhandler(500)
def erro_interno(error):
    return jsonify({'error': 'internal error'}), 500


if __name__ == '__main__':
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DADOS_DIR = os.path.join(BASE_DIR, 'dados')
    print("🚀 Iniciando SGMRP (stub)")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True)
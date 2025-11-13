from flask import Flask, request, jsonify, render_template, session, flash, redirect, url_for, abort
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
    validar_username,
    validar_senha,
    validar_login,
    salvar_novo_lote,
    _load_lotes_data,
    _load_unidades_data,
    carregar_lotes_para_dashboard,
    normalizar_precos,
    salvar_mapas_raw,
    calcular_metricas_lotes,
    preparar_dados_entrada_manual,
    reordenar_registro_mapas
)

app = Flask(__name__)
app.secret_key = 'sgmrp_seap_2025_secret_key_desenvolvimento'
app.config['DEBUG'] = True

#FEITOS
@app.route('/')
def index():
    #Página inicial
    return render_template('index.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    #Página de cadastro
    if request.method == 'POST':
        form_data = request.form.to_dict()
        resp = cadastrar_novo_usuario(form_data)

        accept = request.headers.get('Accept', '')
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if request.is_json or is_ajax or 'application/json' in accept:
            return jsonify(resp), (200 if resp.get('ok') else 400)

        if resp.get('ok'):
            flash(resp.get('mensagem', 'Usuário cadastrado com sucesso. Aguarde a aprovação do seu cadastro.'))
            return redirect(url_for('login'))
        else:
            flash(resp.get('mensagem', 'Erro ao cadastrar usuário'))
            return render_template('cadastro.html', form_data=form_data, erro=resp.get('mensagem'))

    return render_template('cadastro.html')

@app.route('/api/validar-campo', methods=['POST'])
def api_validar_campo():
    """Endpoint simples para validação de campos em tempo real.
    Retorna JSON: { 'valido': True, 'mensagem': 'OK' } por enquanto.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        campo = data.get('campo')
        valor = data.get('valor')
        form = data.get('form')
        if isinstance(form, dict):
            result = validar_cadastro_no_usuario(form)
            return jsonify(result), 200

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
                res = validar_username(valor)
                if isinstance(res, dict):
                    res['campo'] = 'usuario'
                return jsonify(res), 200
            if campo == 'senha':
                res = {'valido': True, 'mensagem': 'OK', 'campo': 'senha'}
                return jsonify(res), 200

        default_res = {'valido': True, 'mensagem': 'OK'}
        if campo:
            default_res['campo'] = campo
        return jsonify(default_res), 200
    except Exception:
        return jsonify({'valido': False, 'mensagem': 'Erro interno'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    #Página de login
    if request.method == 'POST':
        form = request.form.to_dict()
        login_val = form.get('usuario') or form.get('email') or form.get('login') or form.get('username')
        senha = form.get('senha')

        result = validar_login(login_val, senha)

        accept = request.headers.get('Accept', '')
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if request.is_json or is_ajax or 'application/json' in accept:
            return jsonify(result), (200 if result.get('ok') else 400)

        if result.get('ok'):
            user = result.get('user') or {}
            session['usuario_logado'] = True
            session['usuario_id'] = user.get('id')
            session['usuario_nome'] = user.get('nome') or user.get('usuario')
            return redirect(url_for('dashboard', login='1'))
        else:
            flash(result.get('mensagem', 'Credenciais inválidas'))
            return render_template('login.html', erro=result.get('mensagem'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Limpa a sessão do usuário e redireciona para a página de login.
    session.pop('usuario_logado', None)
    session.pop('usuario_id', None)
    session.pop('usuario_nome', None)

    accept = request.headers.get('Accept', '')
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if request.is_json or is_ajax or 'application/json' in accept:
        return jsonify({'ok': True, 'mensagem': 'Logout realizado com sucesso.'}), 200

    flash('Você saiu com sucesso.')
    return redirect(url_for('login'))

@app.route('/api/novo-lote', methods=['POST'])
def api_novo_lote():
    # Endpoint para salvar um novo lote via API
    try:
        data = request.get_json(force=True, silent=True) or {}
        res = salvar_novo_lote(data)
        if res.get('success'):
            return jsonify({'success': True, 'id': res.get('id')}), 200
        else:
            return jsonify({'success': False, 'error': res.get('error', 'Erro ao salvar')}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': 'Erro interno'}), 500

@app.route('/dashboard')
def dashboard():
    #Página do dashboard
    mostrar_login_sucesso = request.args.get('login') == '1'
    usuario_nome = session.get('usuario_nome', '')
    dashboard_data = carregar_lotes_para_dashboard()
    lotes = dashboard_data.get('lotes', [])
    mapas_dados = dashboard_data.get('mapas_dados', [])

    return render_template('dashboard.html', lotes=lotes, mapas_dados=mapas_dados,
                           mostrar_login_sucesso=mostrar_login_sucesso,
                           usuario_nome=usuario_nome)

@app.route('/lotes')
def lotes():
    data = carregar_lotes_para_dashboard()
    lotes = data.get('lotes', [])
    mapas = data.get('mapas_dados', [])

    # calcular métricas dos lotes usando função utilitária
    calcular_metricas_lotes(lotes, mapas)

    empresas = []
    seen = set()
    for l in lotes:
        e = (l.get('empresa') or '').strip()
        if e and e not in seen:
            seen.add(e)
            empresas.append(e)
    empresas.sort()
    return render_template('lotes.html', lotes=lotes, empresas=empresas)

@app.route('/lote/<int:lote_id>')
def lote_detalhes(lote_id):
    # Carregar lotes normalizados
    data = carregar_lotes_para_dashboard()
    lotes = data.get('lotes', [])
    mapas_dados = data.get('mapas_dados', [])

    # Encontrar lote pelo id
    lote = None
    for l in lotes:
        try:
            if int(l.get('id')) == int(lote_id):
                lote = l
                break
        except Exception:
            continue

    if lote is None:
        # lote não encontrado
        abort(404)

    # Normalizar precos usando helper centralizado
    lote['precos'] = normalizar_precos(lote.get('precos'))

    # unidades do lote (nomes)
    unidades_lote = lote.get('unidades') or []

    # mapas relacionados ao lote (por enquanto podem estar vazios) - filtrar por id com tolerância de tipos
    mapas_lote = []
    for m in (mapas_dados or []):
        try:
            if int(m.get('lote_id')) == int(lote.get('id')):
                mapas_lote.append(m)
        except Exception:
            continue

    return render_template('lote-detalhes.html', lote=lote, unidades_lote=unidades_lote, mapas_lote=mapas_lote)

@app.route('/api/adicionar-dados', methods=['POST'])
def api_adicionar_dados():
    try:
        data = request.get_json(force=True, silent=True)
        res = salvar_mapas_raw(data)
        if res.get('success'):
            registro = res.get('registro') if res.get('registro') is not None else data
            extra_id = res.get('id')
            registros_processados = 0
            dias_esperados = 0
            try:
                if isinstance(registro, dict):
                    registros_processados = int(registro.get('linhas') or 0)
                    dias_esperados = int(registro.get('colunas_count') or 0)
            except Exception:
                registros_processados = 0
                dias_esperados = 0

            validacao = {
                'valido': True,
                'refeicoes': {
                    'registros_processados': registros_processados,
                    'dias_esperados': dias_esperados
                },
                'siisp': {
                    'mensagem': 'N/A'
                },
                'mensagem_geral': 'Dados salvos'
            }

            operacao = res.get('operacao')
            if not operacao and isinstance(res.get('operacoes'), list) and len(res.get('operacoes')) == 1:
                operacao = res.get('operacoes')[0]

            resp = {'success': True, 'registro': registro, 'validacao': validacao}
            if extra_id is not None:
                resp['id'] = extra_id
            if operacao is not None:
                resp['operacao'] = operacao
            return jsonify(resp), 200
        else:
            return jsonify({'success': False, 'error': res.get('error', 'Erro ao salvar')}), 200
    except Exception:
        return jsonify({'success': False, 'error': 'Erro interno'}), 200

@app.route('/api/entrada-manual', methods=['POST'])
def api_entrada_manual():
    try:
        data = request.get_json(force=True, silent=True) or {}
        
        dados_preparados = preparar_dados_entrada_manual(data)
        if not dados_preparados.get('success'):
            return jsonify({'success': False, 'error': dados_preparados.get('error', 'Erro ao preparar dados')}), 200
        
        res = salvar_mapas_raw(dados_preparados['data'])
        
        if res.get('success'):
            registro = res.get('registro') if res.get('registro') is not None else dados_preparados['data']
            extra_id = res.get('id')
            
            reordenar_registro_mapas(extra_id)
            
            dias_esperados = len(registro.get('datas', []))
            
            validacao = {
                'valido': True,
                'refeicoes': {
                    'registros_processados': dias_esperados,
                    'dias_esperados': dias_esperados
                },
                'mensagem_geral': 'Dados salvos via entrada manual'
            }

            operacao = res.get('operacao')
            if not operacao and isinstance(res.get('operacoes'), list) and len(res.get('operacoes')) == 1:
                operacao = res.get('operacoes')[0]

            resp = {'success': True, 'registro': registro, 'validacao': validacao}
            if extra_id is not None:
                resp['id'] = extra_id
            if operacao is not None:
                resp['operacao'] = operacao
            return jsonify(resp), 200
        else:
            return jsonify({'success': False, 'error': res.get('error', 'Erro ao salvar')}), 200
    except Exception:
        return jsonify({'success': False, 'error': 'Erro interno'}), 200

#NÃO FEITOS

@app.route('/admin/usuarios')
def admin_usuarios():
    return jsonify({'ok': True})


@app.route('/admin/usuarios/<int:user_id>/aprovar', methods=['POST'])
def aprovar_usuario(user_id):
    return jsonify({'ok': True})


@app.route('/admin/usuarios/<int:user_id>/revogar', methods=['POST'])
def revogar_usuario(user_id):
    return jsonify({'ok': True})

@app.route('/api/excluir-dados', methods=['DELETE'])
def api_excluir_dados():
    return jsonify({'ok': True})


@app.route('/api/adicionar-siisp', methods=['POST'])
def api_adicionar_siisp():
    return jsonify({'ok': True})


@app.route('/api/lotes')
def api_lotes():
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
    # Tornar o contexto global sensível à sessão atual
    usuario_logado = session.get('usuario_logado', False)
    usuario_nome = session.get('usuario_nome', '')
    return {
        'app_nome': 'SGMRP',
        'app_versao': 'stub',
        'ano_atual': datetime.now().year,
        'usuario_logado': usuario_logado,
        'usuario_nome': usuario_nome,
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
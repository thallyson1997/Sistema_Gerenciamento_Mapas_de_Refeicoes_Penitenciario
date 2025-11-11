import json
import re
import os
from datetime import datetime
import bcrypt


# ----- Security / Password helpers -----
def _hash_password(senha):
	"""Retorna o hash bcrypt da senha (string). Se bcrypt não estiver disponível, retorna a senha em texto (fallback)."""
	if not senha:
		return ''
	if bcrypt is None:
		# fallback — prefer instalar bcrypt
		return str(senha)
	try:
		pw = str(senha).encode('utf-8')
		hashed = bcrypt.hashpw(pw, bcrypt.gensalt())
		return hashed.decode('utf-8')
	except Exception:
		return str(senha)

# ----- Small form / utility helpers -----
def _first_present(form_data, *names):
	"""Retorna o primeiro valor presente em form_data para os nomes fornecidos.

	Se nenhum estiver presente, retorna None. Não faz strip nem normalização —
	quem chama decide como tratar o valor.
	"""
	if not isinstance(form_data, dict):
		return None
	for n in names:
		if n in form_data:
			return form_data.get(n)
	return None

# ----- User registration & persistence -----
def cadastrar_novo_usuario(form_data=None):
	r = validar_cadastro_no_usuario(form_data)
	if not r.get('valido'):
		return {'ok': False, 'mensagem': r.get('mensagem', 'Validação falhou'), 'campo': r.get('campo')}

	base_dir = os.path.dirname(os.path.dirname(__file__))
	usuarios_path = os.path.join(base_dir, 'dados', 'usuarios.json')
	usuarios = None
	data_wrapped = None
	try:
		data = _load_usuarios_data()
		if isinstance(data, list):
			usuarios = data
		elif isinstance(data, dict) and isinstance(data.get('usuarios'), list):
			usuarios = data.get('usuarios')
			data_wrapped = data
		else:
			usuarios = []
	except Exception:
		usuarios = []

	existing_ids = [u.get('id') for u in usuarios if isinstance(u, dict) and isinstance(u.get('id'), int)]
	new_id = (max(existing_ids) + 1) if existing_ids else 1

	registro = {
		'id': new_id,
		# data de criação do cadastro (ISO 8601)
		'data_criacao': datetime.now().isoformat(),
		'cpf': re.sub(r'\D', '', str(form_data.get('cpf') or '')),
		'email': str(form_data.get('email') or '').strip(),
		'telefone': re.sub(r'\D', '', str(form_data.get('telefone') or '')),
		'matricula': str(form_data.get('matricula') or '').strip(),
		'usuario': str(form_data.get('usuario') or '').strip(),
		'nome': str(form_data.get('nome') or form_data.get('nome_completo') or '').strip(),
		'cargo': str(form_data.get('cargo') or '').strip(),
		'unidade': str(form_data.get('unidade') or '').strip(),
		'motivo': str(
			_first_present(form_data, 'motivo', 'motivo_solicitacao', 'justificativa', 'justificativa_acesso') or ''
		).strip(),
		'concordo': False,
		'ativo': False,
		'senha': _hash_password(form_data.get('senha') or '')
	}

	# normalizar valor do checkbox "concordo" (vários nomes possíveis vindos do form)
	# normalizar aliases do checkbox de aceite: buscar o primeiro nome presente
	_concordo_raw = _first_present(
		form_data,
		'concordo',
		'concordo_termos',
		'aceito',
		'aceito_termos',
		'aceitarTermos',
		'aceitar_termos'
	)
	if _concordo_raw is not None:
		v = str(_concordo_raw).strip().lower()
		if v in ('1', 'true', 'on', 'yes', 'sim', 'y'):
			registro['concordo'] = True

	try:
		usuarios.append(registro)
		os.makedirs(os.path.dirname(usuarios_path), exist_ok=True)
		if data_wrapped is not None:
			data_wrapped['usuarios'] = usuarios
			to_write = data_wrapped
		else:
			to_write = usuarios
		tmp_path = usuarios_path + '.tmp'
		with open(tmp_path, 'w', encoding='utf-8') as f:
			json.dump(to_write, f, ensure_ascii=False, indent=2)
		os.replace(tmp_path, usuarios_path)
		return {'ok': True, 'mensagem': 'Usuário cadastrado com sucesso. Aguarde a aprovação do seu cadastro.', 'id': new_id}
	except Exception as e:
		try:
			print('Erro ao salvar usuário:', e)
		except Exception:
			pass
		return {'ok': False, 'mensagem': 'Erro ao salvar usuário'}


# ----- User validators & lookup -----
def validar_cpf(cpf):
	if not cpf:
		return {'valido': False, 'mensagem': 'CPF inválido'}
	num = re.sub(r'\D', '', str(cpf))

	if len(num) != 11:
		return {'valido': False, 'mensagem': 'CPF inválido'}
	if re.match(r'^(\d)\1{10}$', num):
		return {'valido': False, 'mensagem': 'CPF inválido'}

	s = 0
	for i in range(9):
		s += int(num[i]) * (10 - i)
	d1 = 11 - (s % 11)
	if d1 >= 10:
		d1 = 0
	if d1 != int(num[9]):
		return {'valido': False, 'mensagem': 'CPF inválido'}

	s = 0
	for i in range(10):
		s += int(num[i]) * (11 - i)
	d2 = 11 - (s % 11)
	if d2 >= 10:
		d2 = 0
	if d2 != int(num[10]):
		return {'valido': False, 'mensagem': 'CPF inválido'}

	if _exists_in_usuarios(num, normalize=lambda x: re.sub(r'\D', '', x)):
		return {'valido': False, 'mensagem': 'CPF já cadastrado'}

	return {'valido': True, 'mensagem': 'OK'}

def _load_usuarios_data():
	base_dir = os.path.dirname(os.path.dirname(__file__))
	usuarios_path = os.path.join(base_dir, 'dados', 'usuarios.json')
	if not os.path.isfile(usuarios_path):
		return None
	try:
		with open(usuarios_path, 'r', encoding='utf-8') as f:
			return json.load(f)
	except Exception:
		return None

def _exists_in_usuarios(target, normalize=lambda x: x, active_only=True):
	if target is None:
		return False
	data = _load_usuarios_data()
	if not data:
		return False

	def _search(obj):
		if isinstance(obj, dict):
			# se este dict representa um registro de usuário com flag 'ativo',
			# respeitar active_only: ignorar o registro quando ativo == False
			if active_only and ('ativo' in obj) and isinstance(obj.get('ativo'), bool) and not obj.get('ativo'):
				return False
			for v in obj.values():
				if _search(v):
					return True
		elif isinstance(obj, list):
			for item in obj:
				if _search(item):
					return True
		else:
			try:
				val = str(obj)
			except Exception:
				return False
			if normalize(val) == normalize(target):
				return True
		return False

	return _search(data)

def _find_user(login_value, active_only=True):
	"""Retorna o dicionário do usuário cujo email OU usuario (username) corresponde a login_value.

	A busca por email é case-insensitive; por usuário também. Se nenhum encontrado, retorna None.
	"""
	if login_value is None:
		return None
	data = _load_usuarios_data()
	if not data:
		return None
	# normalizar a lista de usuários
	usuarios = None
	if isinstance(data, list):
		usuarios = data
	elif isinstance(data, dict) and isinstance(data.get('usuarios'), list):
		usuarios = data.get('usuarios')
	else:
		return None

	lv = str(login_value).strip()
	is_email = ('@' in lv)
	for u in usuarios:
		if not isinstance(u, dict):
			continue
		if active_only and isinstance(u.get('ativo'), bool) and not u.get('ativo'):
			continue
		# comparar email
		email = u.get('email')
		if is_email and isinstance(email, str) and email.strip().lower() == lv.lower():
			return u
		# comparar username
		usuario = u.get('usuario')
		if (not is_email) and isinstance(usuario, str) and usuario.strip().lower() == lv.lower():
			return u
	return None

def _check_password(stored_pw, provided_pw):
	"""Verifica se `provided_pw` corresponde a `stored_pw`.

	- Se bcrypt estiver disponível e stored_pw parece ser um hash bcrypt, usa bcrypt.checkpw.
	- Caso contrário, faz comparação direta (fallback).
	"""
	if stored_pw is None:
		return False
	sp = str(stored_pw)
	if not provided_pw:
		return False
	pp = str(provided_pw)
	# detectar hash bcrypt comum que começa com $2b$ ou $2a$ ou $2y$
	if bcrypt is not None and sp.startswith('$2'):
		try:
			return bcrypt.checkpw(pp.encode('utf-8'), sp.encode('utf-8'))
		except Exception:
			return False
	# fallback inseguro
	return sp == pp

def validar_login(login_value, senha):
	"""Valida credenciais de login.

	Retorna um dict:
	  - {'ok': True, 'mensagem': 'OK', 'user': <user_sanitized>} em sucesso
	  - {'ok': False, 'mensagem': '...'} em falha

	Mensagens específicas:
	  - se input parece e-mail e não existe: 'E-mail não cadastrado'
	  - se input parece username e não existe: 'Usuário não cadastrado'
	  - se senha incorreta: 'Senha incorreta'
	"""
	if not login_value:
		return {'ok': False, 'mensagem': 'Informe usuário ou e-mail'}

	is_email = ('@' in str(login_value))
	user = _find_user(login_value, active_only=True)
	if not user:
		return {'ok': False, 'mensagem': 'E-mail não cadastrado' if is_email else 'Usuário não cadastrado'}

	stored = user.get('senha')
	if not _check_password(stored, senha):
		return {'ok': False, 'mensagem': 'Senha incorreta'}

	# sucesso: não retornar a senha
	sanitized = {k: v for k, v in user.items() if k != 'senha'}
	return {'ok': True, 'mensagem': 'Login efetuado com sucesso', 'user': sanitized}

def validar_email(email):
	if not email:
		return {'valido': False, 'mensagem': 'Email inválido'}
	email = email.strip()
	email_regex = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
	if not email_regex.match(email):
		return {'valido': False, 'mensagem': 'Email inválido'}
	# verificar duplicidade (case-insensitive)
	if _exists_in_usuarios(email.lower(), normalize=lambda x: x.lower()):
		return {'valido': False, 'mensagem': 'Email já cadastrado'}
	return {'valido': True, 'mensagem': 'OK'}

def validar_telefone(telefone):
	if not telefone:
		return {'valido': False, 'mensagem': 'Telefone inválido'}
	num = re.sub(r'\D', '', str(telefone))
	if len(num) < 10 or len(num) > 11:
		return {'valido': False, 'mensagem': 'Telefone inválido'}
	if re.match(r'^(\d)\1{9,10}$', num):
		return {'valido': False, 'mensagem': 'Telefone inválido'}
	if _exists_in_usuarios(num, normalize=lambda x: re.sub(r'\D', '', x)):
		return {'valido': False, 'mensagem': 'Telefone já cadastrado'}
	return {'valido': True, 'mensagem': 'OK'}

def validar_matricula(matricula):
	if not matricula:
		return {'valido': False, 'mensagem': 'Matrícula inválida'}
	mat = str(matricula).strip()
	if _exists_in_usuarios(mat, normalize=lambda x: x.strip()):
		return {'valido': False, 'mensagem': 'Matrícula já cadastrada'}
	return {'valido': True, 'mensagem': 'OK'}

def validar_username(username):
	if not username:
		return {'valido': False, 'mensagem': 'Nome de usuário inválido'}
	user = str(username).strip()
	if _exists_in_usuarios(user.lower(), normalize=lambda x: x.lower()):
		return {'valido': False, 'mensagem': 'Nome de usuário já existe'}
	return {'valido': True, 'mensagem': 'OK'}

def validar_senha(senha, confirmar):
	if senha is None or confirmar is None:
		return {'valido': False, 'mensagem': 'Senha inválida'}
	if str(senha) != str(confirmar):
		return {'valido': False, 'mensagem': 'Senhas não coincidem'}
	return {'valido': True, 'mensagem': 'OK'}

def validar_cadastro_no_usuario(form_data):
	if not isinstance(form_data, dict):
		return {'valido': False, 'mensagem': 'Dados do formulário inválidos'}

	cpf = form_data.get('cpf')
	email = form_data.get('email')
	telefone = form_data.get('telefone')
	matricula = form_data.get('matricula')
	usuario = form_data.get('usuario')
	senha = form_data.get('senha')
	confirmar = form_data.get('confirmarSenha') or form_data.get('confirmar')

	r = validar_cpf(cpf)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'CPF inválido'), 'campo': 'cpf'}

	r = validar_email(email)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'Email inválido'), 'campo': 'email'}

	r = validar_telefone(telefone)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'Telefone inválido'), 'campo': 'telefone'}

	r = validar_matricula(matricula)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'Matrícula inválida'), 'campo': 'matricula'}

	r = validar_username(usuario)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'Nome de usuário inválido'), 'campo': 'usuario'}

	r = validar_senha(senha, confirmar)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'Senhas não coincidem'), 'campo': 'senha'}

	# Todas as validações passaram — não salvar aqui, apenas indicar sucesso
	return {'valido': True, 'mensagem': 'Validação OK'}

# ----- Lotes helpers -----
def _load_lotes_data():
	base_dir = os.path.dirname(os.path.dirname(__file__))
	lotes_path = os.path.join(base_dir, 'dados', 'lotes.json')
	if not os.path.isfile(lotes_path):
		return None
	try:
		with open(lotes_path, 'r', encoding='utf-8') as f:
			return json.load(f)
	except Exception:
		return None

def _save_lotes_data(data):
	base_dir = os.path.dirname(os.path.dirname(__file__))
	lotes_path = os.path.join(base_dir, 'dados', 'lotes.json')
	try:
		os.makedirs(os.path.dirname(lotes_path), exist_ok=True)
		tmp_path = lotes_path + '.tmp'
		with open(tmp_path, 'w', encoding='utf-8') as f:
			json.dump(data, f, ensure_ascii=False, indent=2)
		os.replace(tmp_path, lotes_path)
		return True
	except Exception:
		return False

def _load_unidades_data():
	base_dir = os.path.dirname(os.path.dirname(__file__))
	unidades_path = os.path.join(base_dir, 'dados', 'unidades.json')
	if not os.path.isfile(unidades_path):
		return None
	try:
		with open(unidades_path, 'r', encoding='utf-8') as f:
			return json.load(f)
	except Exception:
		return None

def _save_unidades_data(data):
	base_dir = os.path.dirname(os.path.dirname(__file__))
	unidades_path = os.path.join(base_dir, 'dados', 'unidades.json')
	try:
		os.makedirs(os.path.dirname(unidades_path), exist_ok=True)
		tmp_path = unidades_path + '.tmp'
		with open(tmp_path, 'w', encoding='utf-8') as f:
			json.dump(data, f, ensure_ascii=False, indent=2)
		os.replace(tmp_path, unidades_path)
		return True
	except Exception:
		return False

def salvar_novo_lote(payload: dict):
	if not isinstance(payload, dict):
		return {'success': False, 'error': 'Payload inválido'}

	nome = payload.get('nome_lote') or payload.get('nome') or payload.get('nomeLote') or ''
	empresa = payload.get('nome_empresa') or payload.get('empresa') or payload.get('empresa_nome') or ''
	numero_contrato = payload.get('numero_contrato') or payload.get('contrato') or ''
	data_inicio = payload.get('data_inicio') or payload.get('inicio_contrato') or ''
	unidades = payload.get('unidades') or payload.get('unidades[]') or []

	if unidades is None:
		unidades = []
	if isinstance(unidades, str):
		unidades = [u.strip() for u in unidades.split(',') if u.strip()]
	if not isinstance(unidades, list):
		unidades = list(unidades)

	precos = {}
	raw_precos = payload.get('precos') or {}
	if isinstance(raw_precos, dict):
		precos['cafe_interno'] = raw_precos.get('cafe', {}).get('interno') if isinstance(raw_precos.get('cafe'), dict) else raw_precos.get('cafe_interno') or raw_precos.get('cafeInterno')
		precos['cafe_funcionario'] = raw_precos.get('cafe', {}).get('funcionario') if isinstance(raw_precos.get('cafe'), dict) else raw_precos.get('cafe_funcionario') or raw_precos.get('cafeFuncionario')
		precos['almoco_interno'] = raw_precos.get('almoco', {}).get('interno') if isinstance(raw_precos.get('almoco'), dict) else raw_precos.get('almoco_interno') or raw_precos.get('almocoInterno')
		precos['almoco_funcionario'] = raw_precos.get('almoco', {}).get('funcionario') if isinstance(raw_precos.get('almoco'), dict) else raw_precos.get('almoco_funcionario') or raw_precos.get('almocoFuncionario')
		precos['lanche_interno'] = raw_precos.get('lanche', {}).get('interno') if isinstance(raw_precos.get('lanche'), dict) else raw_precos.get('lanche_interno') or raw_precos.get('lancheInterno')
		precos['lanche_funcionario'] = raw_precos.get('lanche', {}).get('funcionario') if isinstance(raw_precos.get('lanche'), dict) else raw_precos.get('lanche_funcionario') or raw_precos.get('lancheFuncionario')
		precos['jantar_interno'] = raw_precos.get('jantar', {}).get('interno') if isinstance(raw_precos.get('jantar'), dict) else raw_precos.get('jantar_interno') or raw_precos.get('jantarInterno')
		precos['jantar_funcionario'] = raw_precos.get('jantar', {}).get('funcionario') if isinstance(raw_precos.get('jantar'), dict) else raw_precos.get('jantar_funcionario') or raw_precos.get('jantarFuncionario')
	else:
		for k in ['cafe_interno','cafe_funcionario','almoco_interno','almoco_funcionario','lanche_interno','lanche_funcionario','jantar_interno','jantar_funcionario']:
			precos[k] = payload.get(k)

	if not nome or not empresa or not numero_contrato or not data_inicio:
		return {'success': False, 'error': 'Campos obrigatórios faltando'}
	if not unidades or not isinstance(unidades, list) or len(unidades) == 0:
		return {'success': False, 'error': 'Adicione pelo menos uma unidade'}

	data = _load_lotes_data()
	lotes = None
	wrapped = None
	if isinstance(data, list):
		lotes = data
	elif isinstance(data, dict) and isinstance(data.get('lotes'), list):
		lotes = data.get('lotes')
		wrapped = data
	else:
		lotes = []

	existing_ids = [l.get('id') for l in lotes if isinstance(l, dict) and isinstance(l.get('id'), int)]
	new_id = (max(existing_ids) + 1) if existing_ids else 0

	input_unidades = unidades
	unit_ids = []
	created_unit_ids = []

	units_data = _load_unidades_data()
	units_list = []
	units_wrapped = None
	if isinstance(units_data, list):
		units_list = units_data
	elif isinstance(units_data, dict) and isinstance(units_data.get('unidades'), list):
		units_list = units_data.get('unidades')
		units_wrapped = units_data
	else:
		units_list = []

	existing_unit_ids = [u.get('id') for u in units_list if isinstance(u, dict) and isinstance(u.get('id'), int)]
	next_unit_id = (max(existing_unit_ids) + 1) if existing_unit_ids else 0

	def _is_int_like(x):
		try:
			int(x)
			return True
		except Exception:
			return False

	if isinstance(input_unidades, list) and input_unidades and all(_is_int_like(u) for u in input_unidades):
		unit_ids = [int(u) for u in input_unidades]
	else:
		for raw in (input_unidades or []):
			name = str(raw).strip()
			if not name:
				continue
			found = None
			for u in units_list:
				if not isinstance(u, dict):
					continue
				if isinstance(u.get('nome'), str) and u.get('nome').strip().lower() == name.lower():
					found = u
					break
			if found:
				found['lote_id'] = new_id
				unit_ids.append(found.get('id'))
			else:
				uid = next_unit_id
				new_unit = {
					'id': uid,
					'nome': name,
					'lote_id': new_id,
					'criado_em': datetime.now().isoformat()
				}
				units_list.append(new_unit)
				unit_ids.append(uid)
				created_unit_ids.append(uid)
				next_unit_id += 1

	if units_wrapped is not None:
		units_wrapped['unidades'] = units_list
		to_write_units = units_wrapped
	else:
		to_write_units = units_list

	if not _save_unidades_data(to_write_units):
		return {'success': False, 'error': 'Erro ao salvar unidades'}

	lote_record = {
		'id': new_id,
		'nome': str(nome),
		'empresa': str(empresa),
		'numero_contrato': str(numero_contrato),
		'data_inicio': str(data_inicio),
		'unidades': unit_ids,
		'precos': precos,
		'ativo': True,
		'criado_em': datetime.now().isoformat()
	}

	lotes.append(lote_record)
	if wrapped is not None:
		wrapped['lotes'] = lotes
		to_write = wrapped
	else:
		to_write = lotes

	ok = _save_lotes_data(to_write)
	if not ok:
		if created_unit_ids:
			try:
				ud = _load_unidades_data() or []
				if isinstance(ud, dict) and isinstance(ud.get('unidades'), list):
					lst = ud.get('unidades')
					lst = [u for u in lst if not (isinstance(u, dict) and u.get('id') in created_unit_ids)]
					ud['unidades'] = lst
				else:
					lst = [u for u in (ud if isinstance(ud, list) else []) if not (isinstance(u, dict) and u.get('id') in created_unit_ids)]
					ud = lst
				_save_unidades_data(ud)
			except Exception:
				pass
		return {'success': False, 'error': 'Erro ao salvar lote'}
	return {'success': True, 'id': new_id}


# ----- Dashboard loader (reusable) -----
def carregar_lotes_para_dashboard():
	"""Carrega e normaliza os lotes e unidades para uso no dashboard.

	Retorna um dicionário: { 'lotes': [...], 'mapas_dados': [...] }
	onde cada lote é um dict compatível com o que o template espera
	(campos: id, nome, empresa, contrato, data_inicio, ativo, unidades, precos, ...).
	"""
	lotes_raw = _load_lotes_data() or []
	unidades_raw = _load_unidades_data() or []

	# normalizar lista de unidades como lista de objetos
	unidades_list = []
	if isinstance(unidades_raw, dict) and isinstance(unidades_raw.get('unidades'), list):
		unidades_list = unidades_raw.get('unidades')
	elif isinstance(unidades_raw, list):
		unidades_list = unidades_raw

	# construir mapa id -> nome
	unidades_map = {}
	for u in unidades_list:
		if isinstance(u, dict) and isinstance(u.get('id'), int):
			unidades_map[int(u.get('id'))] = u.get('nome')

	lotes = []
	if isinstance(lotes_raw, dict) and isinstance(lotes_raw.get('lotes'), list):
		src_lotes = lotes_raw.get('lotes')
	elif isinstance(lotes_raw, list):
		src_lotes = lotes_raw
	else:
		src_lotes = []

	for l in src_lotes:
		if not isinstance(l, dict):
			continue
		raw_unidades = l.get('unidades') or []
		unidades_final = []
		if isinstance(raw_unidades, list) and raw_unidades:
			# detect numeric ids
			if all(isinstance(x, int) or (isinstance(x, str) and x.isdigit()) for x in raw_unidades):
				for x in raw_unidades:
					try:
						uid = int(x)
						unidades_final.append(unidades_map.get(uid, str(uid)))
					except Exception:
						unidades_final.append(str(x))
			else:
				unidades_final = [str(x) for x in raw_unidades if x]

		# Normalizar campo de precos: aceita dicts nested, dicts com chaves planas
		# (ex: 'cafe_interno') ou strings JSON. Retorna sempre a forma nested
		# { 'cafe': {'interno': float, 'funcionario': float}, ... }
		def _to_float(v):
			try:
				return float(str(v).replace(',', '.'))
			except Exception:
				return 0.0

		def _normalize_precos(raw_precos):
			meals = ('cafe', 'almoco', 'lanche', 'jantar')
			# resultado nested
			res = {m: {'interno': 0.0, 'funcionario': 0.0} for m in meals}
			if raw_precos is None:
				return res
			# Se for string, tentar decodificar JSON ou extrair pares chave:valor
			if isinstance(raw_precos, str):
				txt = raw_precos.strip()
				# tentar JSON primeiro
				try:
					parsed = json.loads(txt)
				except Exception:
					# tentar trocar aspas simples por duplas e carregar
					try:
						parsed = json.loads(txt.replace("'", '"'))
					except Exception:
						# extrair pares simples como key: value ou key=value
						parsed = {}
						for m in re.finditer(r"([a-zA-Z0-9_]+)\s*[:=]\s*['\"]?([0-9\.,]+)['\"]?", txt):
							k = m.group(1)
							v = m.group(2)
							parsed[k] = v
				# usar parsed abaixo
				raw = parsed
			elif isinstance(raw_precos, dict):
				raw = raw_precos
			else:
				# formatos inesperados
				return res

			# se raw tiver as chaves nested por refeição
			if isinstance(raw, dict):
				for meal in meals:
					val = raw.get(meal)
					if isinstance(val, dict):
						res[meal]['interno'] = _to_float(val.get('interno') or val.get('interno_val') or 0)
						res[meal]['funcionario'] = _to_float(val.get('funcionario') or val.get('funcionario_val') or 0)
					else:
						# procurar chaves planas como cafe_interno, cafe_funcionario
						int_key = f"{meal}_interno"
						func_key = f"{meal}_funcionario"
						if int_key in raw or func_key in raw:
							res[meal]['interno'] = _to_float(raw.get(int_key) or raw.get(int_key.replace('_', '')))
							res[meal]['funcionario'] = _to_float(raw.get(func_key) or raw.get(func_key.replace('_', '')))
						# também aceitar chaves estilo camelCase
						int_key2 = f"{meal}Interno"
						func_key2 = f"{meal}Funcionario"
						if (res[meal]['interno'] == 0.0) and int_key2 in raw:
							res[meal]['interno'] = _to_float(raw.get(int_key2))
						if (res[meal]['funcionario'] == 0.0) and func_key2 in raw:
							res[meal]['funcionario'] = _to_float(raw.get(func_key2))
				# garantir floats
				for m in meals:
					res[m]['interno'] = _to_float(res[m]['interno'])
					res[m]['funcionario'] = _to_float(res[m]['funcionario'])
				return res
			# fallback
			return res

		# garantir campos numéricos usados pelo template com valores padrão
		try:
			refeicoes_mes = int(l.get('refeicoes_mes') if l.get('refeicoes_mes') is not None else (l.get('refeicoes') or 0))
		except Exception:
			try:
				refeicoes_mes = int(float(l.get('refeicoes') or 0))
			except Exception:
				refeicoes_mes = 0
		try:
			custo_mes = float(l.get('custo_mes') if l.get('custo_mes') is not None else l.get('custo') or 0.0)
		except Exception:
			try:
				custo_mes = float(str(l.get('custo') or 0).replace(',', '.'))
			except Exception:
				custo_mes = 0.0
		try:
			desvio_mes = float(l.get('desvio_mes') if l.get('desvio_mes') is not None else l.get('desvio') or 0.0)
		except Exception:
			try:
				desvio_mes = float(str(l.get('desvio') or 0).replace(',', '.'))
			except Exception:
				desvio_mes = 0.0
		try:
			meses_cadastrados = int(l.get('meses_cadastrados') if l.get('meses_cadastrados') is not None else l.get('meses') or 0)
		except Exception:
			meses_cadastrados = 0

		# padronizar conformidade: garantir float e default 0.0
		try:
			conformidade_val = l.get('conformidade')
			if conformidade_val is None:
				conformidade = 0.0
			else:
				# aceitar strings com vírgula ou ponto, ints etc.
				conformidade = float(str(conformidade_val).replace(',', '.'))
		except Exception:
			conformidade = 0.0

		lote_obj = {
			'id': l.get('id'),
			'nome': l.get('nome') or l.get('nome_lote') or '',
			'empresa': l.get('empresa') or '',
			'contrato': l.get('numero_contrato') or l.get('contrato') or '',
			'data_inicio': l.get('data_inicio'),
			'ativo': l.get('ativo', True),
			'unidades': unidades_final,
			'precos': _normalize_precos(l.get('precos')),
			'refeicoes_mes': refeicoes_mes,
			'custo_mes': custo_mes,
			'desvio_mes': desvio_mes,
			'meses_cadastrados': meses_cadastrados,
			'refeicoes': l.get('refeicoes'),
			'conformidade': conformidade,
			'alertas': l.get('alertas')
		}
		lotes.append(lote_obj)

	mapas_dados = []
	return {'lotes': lotes, 'mapas_dados': mapas_dados}
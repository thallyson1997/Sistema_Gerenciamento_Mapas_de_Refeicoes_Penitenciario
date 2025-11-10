import json
import re
import os

def cadastrar_novo_usuario(form_data=None):
	resp = {"ok": True}
	try:
		print(json.dumps(resp, ensure_ascii=False))
	except Exception:
		print(resp)
	return resp


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

def _exists_in_usuarios(target, normalize=lambda x: x):
	if target is None:
		return False
	data = _load_usuarios_data()
	if not data:
		return False

	def _search(obj):
		if isinstance(obj, dict):
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

def validar_userna(username):
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

	r = validar_userna(usuario)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'Nome de usuário inválido'), 'campo': 'usuario'}

	r = validar_senha(senha, confirmar)
	if not r.get('valido'):
		return {'valido': False, 'mensagem': r.get('mensagem', 'Senhas não coincidem'), 'campo': 'senha'}

	# Todas as validações passaram — não salvar aqui, apenas indicar sucesso
	return {'valido': True, 'mensagem': 'Validação OK'}

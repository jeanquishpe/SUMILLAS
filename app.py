# Importaciones actualizadas
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import os
import json
import logging
from pathlib import Path
from flask_wtf.csrf import CSRFProtect, generate_csrf  # Asegúrate de importar generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, FileField, SelectMultipleField
from wtforms.validators import DataRequired, Email
from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=lambda: csrf._get_token())
# Configuración de la aplicación
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu-clave-secreta-muy-segura'  # Cambia esto en producción
csrf = CSRFProtect(app)

# Configuración de rutas de archivos
UPLOAD_FOLDER = 'uploads'
DOCUMENTS_FILE = 'documents.json'
SUMILLAS_FILE = 'sumillas.json'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log'
)
logger = logging.getLogger(__name__)

# Formulario WTF para Sumillas
class SumillaForm(FlaskForm):
    nombre_documento = StringField('Nombre del Documento', validators=[DataRequired()])
    fecha_recepcion = StringField('Fecha de Recepción', validators=[DataRequired()])
    cargo = StringField('Cargo', validators=[DataRequired()])
    institucion = StringField('Institución', validators=[DataRequired()])
    asunto = TextAreaField('Asunto', validators=[DataRequired()])
    usuarios_etiquetados = SelectMultipleField('Usuarios Etiquetados', validators=[DataRequired()])
    etiquetas = StringField('Etiquetas')
    archivo = FileField('Archivo')


# Rutas y funciones auxiliares

# Función para verificar si un archivo tiene una extensión permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx', 'xls', 'xlsx'}

# Funciones para cargar y guardar datos en formato JSON
def load_users():
    try:
        if os.path.exists('users.json'):
            with open('users.json', 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        logger.error(f"Error loading users: {e}")
        return {}

def save_users(users):
    try:
        with open('users.json', 'w') as f:
            json.dump(users, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Error saving users: {e}")
        return False


def load_documents():
    try:
        if os.path.exists(DOCUMENTS_FILE):
            with open(DOCUMENTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Error loading documents: {str(e)}")
        return []

def load_sumillas():
    try:
        if os.path.exists(SUMILLAS_FILE):
            with open(SUMILLAS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Error loading sumillas: {str(e)}")
        return []

def save_sumillas(sumillas):
    try:
        with open(SUMILLAS_FILE, 'w', encoding='utf-8') as f:
            json.dump(sumillas, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Error saving sumillas: {str(e)}")
        return False

def save_documents(documents):
    try:
        with open(DOCUMENTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(documents, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Error saving documents: {str(e)}")
        return False

def add_notification(user_id, message, notification_type='info'):
    try:
        users = load_users()
        if user_id in users:
            if 'notifications' not in users[user_id]:
                users[user_id]['notifications'] = []
            
            notification = {
                'id': len(users[user_id]['notifications']) + 1,
                'message': message,
                'type': notification_type,
                'timestamp': datetime.now().isoformat(),
                'read': False
            }
            
            users[user_id]['notifications'].append(notification)
            save_users(users)
            return True
    except Exception as e:
        logger.error(f"Error adding notification: {str(e)}")
    return False

# Decoradores
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        users = load_users()
        if session['user_id'] not in users or users[session['user_id']]['role'] != 'admin':
            flash('Acceso denegado. Se requieren privilegios de administrador.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Context processor y filtros
@app.template_filter('datetime')
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime("%d/%m/%Y %H:%M")

@app.context_processor
def utility_processor():
    def get_notifications_count():
        if 'user_id' not in session:
            return 0
        try:
            users = load_users()
            current_user = users.get(session['user_id'], {})
            notifications = current_user.get('notifications', [])
            return sum(1 for n in notifications if not n.get('read', False))
        except Exception as e:
            logger.error(f"Error counting notifications: {str(e)}")
            return 0

    def get_user_data():
        if 'user_id' not in session:
            return {}
        users = load_users()
        return users.get(session['user_id'], {})

    return {
        'notifications_count': get_notifications_count(),
        'current_user': session.get('user_id', None),
        'user_data': get_user_data(),
        'is_admin': session.get('role') == 'admin',
        'current_year': datetime.now().year,
        'app_name': 'GESTI HEQ'
    }

# Rutas de autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = load_users()
        
        if username in users and check_password_hash(users[username]['password'], password):
            if not users[username].get('active', True):
                flash('Usuario inactivo. Contacte al administrador.', 'error')
                return render_template('login.html')
                
            session['user_id'] = username
            session['role'] = users[username]['role']
            flash('Inicio exitoso', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Usuario o contraseña incorrectos', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada exitosamente', 'success')
    return redirect(url_for('login'))

# Rutas principales
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('admin/dashboard.html')

# Rutas de usuarios
@app.route('/users')
@admin_required
def users_index():
    all_users = load_users()
    return render_template('users/index.html', users=all_users)

@app.route('/users/store', methods=['POST'])
@admin_required
def users_store():
    try:
        data = request.get_json()
        users = load_users()
        
        # Check if the username already exists
        if data['username'] in users:
            return jsonify({'error': 'El nombre de usuario ya existe'}), 400

        # Create a new user
        new_user = {
            'username': data['username'],
            'password': generate_password_hash(data['password']),
            'fullname': data['fullname'],
            'email': data['email'],
            'role': data['role'],
            'active': data.get('active', True),
            'permissions': data.get('permissions', {}),
            'created_at': datetime.now().isoformat(),
            'notifications': []
        }
        
        users[data['username']] = new_user
        
        if save_users(users):
            logger.info(f"Usuario creado: {data['username']}")
            return jsonify({'success': True}), 201
        else:
            return jsonify({'error': 'Error al guardar el usuario'}), 500
        
    except Exception as e:
        logger.error(f"Error in users_store: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/edit/<username>', methods=['GET', 'POST'])  # Añadir 'POST' aquí
@admin_required
def users_edit(username):
    users = load_users()
    user = users.get(username)
    if not user:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('users_index'))

    if request.method == 'POST':
        try:
            data = request.get_json()
            user.update({
                'fullname': data['fullname'],
                'email': data['email'],
                'role': data['role'],
                'active': data.get('active', True),
                'permissions': data.get('permissions', {})
            })

            if data.get('password'):
                user['password'] = generate_password_hash(data['password'])

            if save_users(users):
                logger.info(f"Usuario actualizado: {username}")
                return jsonify({'success': True})
            else:
                return jsonify({'error': 'Error al guardar los cambios'}), 500

        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            return jsonify({'error': 'Error interno del servidor'}), 500

    # GET: Mostrar formulario de edición
    return render_template('users/edit.html', user=user)

@app.route('/users/<username>/toggle-status', methods=['POST'])
@admin_required
def toggle_user_status(username):
    try:
        if username == 'admin':
            return jsonify({'error': 'No se puede desactivar el usuario administrador'}), 400
            
        users = load_users()
        if username not in users:
            return jsonify({'error': 'Usuario no encontrado'}), 404
            
        users[username]['active'] = not users[username]['active']
        
        if save_users(users):
            status = 'activado' if users[username]['active'] else 'desactivado'
            logger.info(f"Usuario {username} {status}")
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Error al guardar los cambios'}), 500
            
    except Exception as e:
        logger.error(f"Error toggling user status: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

    if request.method == 'POST':
        # Lógica para crear un usuario
        pass
    return render_template('users/create.html')

# Rutas de usuarios
@app.route('/users/create', methods=['GET', 'POST'])
@admin_required
def users_create():
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validar campos requeridos
            required_fields = ['username', 'password', 'fullname', 'email', 'role']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'error': f'Campo requerido: {field}'}), 400
            
            users = load_users()
            
            # Verificar si el usuario existe
            if data['username'] in users:
                return jsonify({'error': 'El usuario ya existe'}), 400
            
            # Crear usuario
            new_user = {
                'username': data['username'],
                'password': generate_password_hash(data['password']),
                'fullname': data['fullname'],
                'email': data['email'],
                'role': data['role'],
                'active': data.get('active', True),
                'permissions': data.get('permissions', {}),
                'notifications': [],
                'created_at': datetime.now().isoformat(),
                'created_by': session['user_id']
            }
            
            users[data['username']] = new_user
            
            if save_users(users):
                logger.info(f"Usuario creado: {data['username']}")
                return jsonify({'success': True}), 201
            else:
                return jsonify({'error': 'Error al guardar'}), 500
                
        except Exception as e:
            logger.error(f"Error en users_create: {str(e)}")
            return jsonify({'error': 'Error interno'}), 500
    
    # GET: Mostrar formulario
    return render_template('users/create.html')
# Rutas de sumillas
@app.route('/sumillas')
@login_required
def sumillas_index():
    users = load_users()
    usuarios_secundarios = {username: info for username, info in users.items() 
                          if info.get('role') == 'user' and info.get('active', True)}
    return render_template('sumillas/form.html', usuarios_secundarios=usuarios_secundarios)

@app.route('/mis-sumillas')
@login_required
def mis_sumillas():
    sumillas = load_sumillas()
    users = load_users()
    mis_sumillas = [
        sumilla for sumilla in sumillas 
        if session['user_id'] in sumilla.get('usuarios_etiquetados', [])
    ]
    return render_template('sumillas/mis_sumillas.html', sumillas=mis_sumillas, users=users)

@app.route('/sumillas-enviadas')
@admin_required
def sumillas_enviadas():
    sumillas = load_sumillas()
    users = load_users()
    return render_template('sumillas/enviadas.html', sumillas=sumillas, users=users)

@app.route('/sumilla/<int:sumilla_id>/responder', methods=['POST'])
@login_required
def responder_sumilla(sumilla_id):
    try:
        comentario = request.form.get('comentario')
        if not comentario:
            return jsonify({'error': 'El comentario es requerido'}), 400

        sumillas = load_sumillas()
        sumilla = next((s for s in sumillas if s.get('id') == sumilla_id), None)
        
        if not sumilla:
            return jsonify({'error': 'Sumilla no encontrada'}), 404
            
        if session['user_id'] not in sumilla['usuarios_etiquetados']:
            return jsonify({'error': 'No tienes permiso para responder a esta sumilla'}), 403

        # Procesar archivo si fue enviado
        archivo_path = None
        if 'documento_respuesta' in request.files:
            archivo = request.files['documento_respuesta']
            if archivo and archivo.filename:
                if not allowed_file(archivo.filename):
                    return jsonify({'error': 'Tipo de archivo no permitido'}), 400
                
                # Crear directorio para respuestas
                respuestas_dir = os.path.join(UPLOAD_FOLDER, 'atencion_sumillas')
                os.makedirs(respuestas_dir, exist_ok=True)
                
                # Crear nombre del archivo
                nombre_base = f"Atención Sumilla ({sumilla['nombre_documento']})"
                extension = archivo.filename.rsplit('.', 1)[1].lower()
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                nuevo_nombre = f"{nombre_base}_{timestamp}.{extension}"
                
                archivo_path = os.path.join(respuestas_dir, nuevo_nombre)
                archivo.save(archivo_path)

        # Agregar la respuesta
        sumilla['respuestas'][session['user_id']] = {
            'comentario': comentario,
            'fecha': datetime.now().isoformat(),
            'documento_path': archivo_path
        }
        
        # Agregar al historial
        sumilla['historial'].append({
            'accion': 'Respuesta agregada',
            'fecha': datetime.now().isoformat(),
            'usuario': session['user_id'],
            'comentario': comentario,
            'tiene_documento': bool(archivo_path)
        })
        
        # Verificar si todos han respondido
        if len(sumilla['respuestas']) == len(sumilla['usuarios_etiquetados']):
            sumilla['estado'] = 'completado'
        
        if save_sumillas(sumillas):
            # Notificar al creador
            add_notification(
                sumilla['created_by'],
                f'Nueva respuesta en la sumilla {sumilla["nombre_documento"]} por {session["user_id"]}',
                'info'
            )
            return jsonify({'success': True})
        else:
            if archivo_path and os.path.exists(archivo_path):
                os.remove(archivo_path)
            return jsonify({'error': 'Error al guardar la respuesta'}), 500
            
    except Exception as e:
        logger.error(f"Error in responder_sumilla: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/sumillas/create', methods=['POST'])
@admin_required
def sumillas_store():
    try:
        required_fields = ['nombre_documento', 'fecha_recepcion', 'usuarios_etiquetados', 'cargo', 'institucion', 'asunto']

        for field in required_fields:
            if not request.form.get(field):
                flash(f'El campo {field} es requerido', 'error')
                return redirect(request.referrer or url_for('sumillas_index'))  # Redirige a la página anterior o a 'sumillas_index'

        usuarios_etiquetados = request.form.getlist('usuarios_etiquetados')

        if not usuarios_etiquetados: # Validación de que al menos un usuario esté etiquetado
            flash('Debes etiquetar al menos un usuario', 'error')
            return redirect(request.referrer or url_for('sumillas_index'))

        archivo_path = None
        if 'archivo' in request.files:
            archivo = request.files['archivo']
            if archivo and archivo.filename:
                if not allowed_file(archivo.filename):
                    flash('Tipo de archivo no permitido', 'error')
                    return redirect(request.referrer or url_for('sumillas_index'))

                sumillas_dir = os.path.join(UPLOAD_FOLDER, 'sumillas')
                os.makedirs(sumillas_dir, exist_ok=True)
                filename = secure_filename(archivo.filename)

                # Generar un nombre de archivo único con marca de tiempo
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{timestamp}_{filename}" # Nombre unico

                archivo_path = os.path.join(sumillas_dir, filename)
                archivo.save(archivo_path)

        etiquetas = [tag.strip() for tag in request.form.get('etiquetas', '').split(',') if tag.strip()] if request.form.get('etiquetas') else [] # Limpieza de etiquetas

        sumillas = load_sumillas()
        new_sumilla = {
            'id': len(sumillas) + 1,
            'nombre_documento': request.form['nombre_documento'],
            'fecha_recepcion': request.form['fecha_recepcion'],
            'usuarios_etiquetados': usuarios_etiquetados,
            'cargo': request.form['cargo'],
            'institucion': request.form['institucion'],
            'asunto': request.form['asunto'],
            'etiquetas': etiquetas,
            'estado': 'pendiente',
            'file_path': archivo_path,
            'created_by': session['user_id'],
            'created_at': datetime.now().isoformat(),
            'respuestas': {},
            'historial': [{'accion': 'Creación de sumilla', 'fecha': datetime.now().isoformat(), 'usuario': session['user_id']}]
        }

        sumillas.append(new_sumilla)

        if save_sumillas(sumillas):
            for usuario in usuarios_etiquetados:
                add_notification(usuario, f'Has sido etiquetado en una nueva sumilla: {new_sumilla["nombre_documento"]}', 'info')
            flash('Sumilla creada exitosamente', 'success')
            return redirect(url_for('sumillas_enviadas'))

        if archivo_path and os.path.exists(archivo_path):
            os.remove(archivo_path)  # Elimina el archivo si falla el guardado de la sumilla
        flash('Error al guardar la sumilla', 'error')

    except Exception as e:
        logger.error(f"Error in sumillas_store: {str(e)}")
        flash('Error al crear la sumilla', 'error')

    return redirect(url_for('sumillas_index')) # Redirección en caso de error

@app.route('/sumilla/<int:sumilla_id>/ver')
@login_required
def sumillas_show(sumilla_id):
    try:
        sumillas = load_sumillas()
        sumilla = next((s for s in sumillas if s.get('id') == sumilla_id), None)
        
        if not sumilla:
            flash('Sumilla no encontrada', 'error')
            return redirect(url_for('mis_sumillas'))
        
        # Verificar permisos
        if not (session.get('role') == 'admin' or 
                session['user_id'] == sumilla.get('created_by') or
                session['user_id'] in sumilla.get('usuarios_etiquetados', [])):
            flash('No tienes permiso para ver esta sumilla', 'error')
            return redirect(url_for('mis_sumillas'))
        
        users = load_users()
        return render_template('sumillas/view.html', sumilla=sumilla, users=users)
        
    except Exception as e:
        logger.error(f"Error viewing sumilla: {str(e)}")
        flash('Error al cargar la sumilla', 'error')
        return redirect(url_for('mis_sumillas'))

@app.route('/sumillas/download/<path:filename>')
@login_required
def sumillas_download(filename):
    try:
        sumillas = load_sumillas()
        sumilla = next((s for s in sumillas if s['file_path'] and s['file_path'].split('/')[-1] == filename), None)
        
        if not sumilla:
            raise FileNotFoundError('Sumilla no encontrada')

        file_path = sumilla['file_path']
        if not os.path.exists(file_path):
            raise FileNotFoundError('Archivo no encontrado')
            
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading sumilla: {str(e)}")
        flash('Error al descargar el documento', 'error')
        return redirect(request.referrer or url_for('mis_sumillas'))

@app.route('/documentos')
@login_required
def documentos():
    # Cargar documentos y usuarios
    documents = load_documents()
    users = load_users()

    # Obtener el usuario actual
    current_user = users.get(session['user_id'])

    # Verificar si el usuario actual es un administrador
    if current_user is None:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('dashboard'))

    if current_user['role'] != 'admin':
        # Filtrar documentos para que solo el usuario actual o los compartidos con él puedan ver
        documents = [
            doc for doc in documents 
            if doc['created_by'] == session['user_id'] or session['user_id'] in doc.get('shared_with', [])
        ]

    # Generar el token CSRF
    csrf_token = lambda: generate_csrf()

    # Renderizar el template y pasar el token CSRF
    return render_template(
        'documentos/index.html', 
        documents=documents,
        users=users,
        csrf_token=csrf_token
    )

@app.route('/documentos/download/<path:filename>')
@login_required
def documentos_download(filename):
    try:
        documents = load_documents()
        document = next((d for d in documents if d['filename'] == filename), None)
        
        if not document:
            flash('Documento no encontrado', 'error')
            return redirect(url_for('documentos'))

        file_path = document['file_path']
        if not os.path.exists(file_path):
            flash('Archivo no encontrado en el sistema', 'error')
            return redirect(url_for('documentos'))
            
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading document: {str(e)}")
        flash('Error al descargar el documento', 'error')
        return redirect(url_for('documentos'))

@app.route('/documentos/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_documento(doc_id):
    try:
        documents = load_documents()
        doc = next((d for d in documents if d['id'] == doc_id), None)
        
        if not doc:
            flash('Documento no encontrado', 'error')
            return redirect(url_for('documentos'))

        # Verificar permisos: solo admin o creador puede eliminar
        if not (session['role'] == 'admin' or doc['created_by'] == session['user_id']):
            flash('No tienes permiso para eliminar este documento', 'error')
            return redirect(url_for('documentos'))

        # Eliminar archivo físico
        if os.path.exists(doc['file_path']):
            os.remove(doc['file_path'])

        # Eliminar de la lista
        documents = [d for d in documents if d['id'] != doc_id]
        save_documents(documents)

        flash('Documento eliminado exitosamente', 'success')
        return redirect(url_for('documentos'))

    except Exception as e:
        logger.error(f"Error deleting document: {str(e)}")
        flash('Error al eliminar el documento', 'error')
        return redirect(url_for('documentos'))

@app.route('/documentos/upload', methods=['POST'])
@login_required
def upload_documento():
    try:
        if 'document' not in request.files:
            flash('No se seleccionó ningún archivo', 'error')
            return redirect(url_for('documentos'))
            
        file = request.files['document']
        if file.filename == '':
            flash('No se seleccionó ningún archivo', 'error')
            return redirect(url_for('documentos'))

        if not file.filename.lower().endswith('.pdf'):
            flash('Solo se permiten archivos PDF', 'error')
            return redirect(url_for('documentos'))
        
        required_fields = ['gerencia', 'year', 'month', 'document_name', 'document_type', 'subject']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'El campo {field} es requerido', 'error')
                return redirect(url_for('documentos'))
        
        gerencia = request.form['gerencia']
        year = request.form['year']
        month = request.form['month']
        document_name = request.form['document_name']
        
        base_path = os.path.join(UPLOAD_FOLDER, 
                               secure_filename(gerencia),
                               str(year),
                               secure_filename(month))
        os.makedirs(base_path, exist_ok=True)
        
        new_filename = f"{secure_filename(document_name)}.pdf"
        file_path = os.path.join(base_path, new_filename)
        
        if os.path.exists(file_path):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            new_filename = f"{secure_filename(document_name)}_{timestamp}.pdf"
            file_path = os.path.join(base_path, new_filename)
        
        file.save(file_path)
        
        doc_data = {
            'id': len(load_documents()) + 1,
            'filename': new_filename,
            'original_name': file.filename,
            'document_name': document_name,
            'document_type': request.form['document_type'],
            'gerencia': gerencia,
            'year': year,
            'month': month,
            'subject': request.form['subject'],
            'from_person': request.form.get('from', ''),
            'to_person': request.form.get('to', ''),
            'created_by': session['user_id'],
            'created_at': datetime.now().isoformat(),
            'file_path': file_path
        }
        
        documents = load_documents()
        documents.append(doc_data)
        if not save_documents(documents):
            try:
                os.remove(file_path)
            except:
                pass
            flash('Error al guardar la información del documento', 'error')
            return redirect(url_for('documentos'))
        
        flash('Documento subido exitosamente', 'success')
        return redirect(url_for('documentos'))
        
    except Exception as e:
        logger.error(f"Error in upload_documento: {str(e)}")
        flash('Error al subir el documento', 'error')
        return redirect(url_for('documentos'))

@app.route('/refresh-csrf')
def refresh_csrf():
    return jsonify({'csrf_token': generate_csrf()})

if __name__ == '__main__':
    # Crear usuario admin
    users = load_users()
    if 'admin' not in users:
        users['admin'] = {
            'username': 'admin',
            'password': generate_password_hash('admin123'),
            'fullname': 'Administrador',
            'email': 'admin@example.com',
            'role': 'admin',
            'active': True,
            'permissions': {'documents': True, 'sumillas': True, 'reports': True, 'users': True},
            'notifications': [],
            'created_at': datetime.now().isoformat()
        }
        save_users(users)

    app.run(debug=True, host='0.0.0.0', port=5000)
from ast                import If
from threading          import activeCount
from time               import time
from flask              import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_mysqldb      import MySQL,MySQLdb
from flask_mail         import Mail, Message
from flask_bcrypt       import bcrypt
from flask_login        import LoginManager, login_user, logout_user, login_required, login_manager
from flask_wtf.csrf     import CSRFProtect
from functools          import wraps
from werkzeug.utils     import secure_filename
from datetime           import date, datetime
import base64
import pdfkit
import os

RMApp                                   = Flask(__name__)
mysql                                   = MySQL(RMApp)
csrf=CSRFProtect()
RMApp.config['MYSQL_HOST']              = 'localhost'
RMApp.config['MYSQL_USER']              = 'root'
RMApp.config['MYSQL_PASSWORD']          = 'mysql'
RMApp.config['MYSQL_DB']                = 'rm'
RMApp.config['MYSQL_CURSORCLASS']       = 'DictCursor'
RMApp.config['UPLOAD_FOLDER']           = './static/img/'
RMApp.config['UPLOAD_FOLDER_PDF']       = './static/pdf/'
RMApp.config['MAIL_SERVER']             = 'smtp.gmail.com'
RMApp.config['MAIL_USERNAME']           = ''
RMApp.config['MAIL_PASSWORD']           = ''
RMApp.config['MAIL_PORT']               = 587
RMApp.config['MAIL_USE_TLS']            = True
RMApp.config['MAIL_USE_SSL']            = False
RMApp.config['MAIL_ASCII_ATTACHMENTS']  = True
mail    =   Mail(RMApp)
options = {
    'page-size': 'Letter',
    'margin-top': '0.75in',
    'margin-right': '0.75in',
    'margin-bottom': '0.75in',
    'margin-left': '0.75in',
    'encoding': "UTF-8",
    'custom-header' : [
        ('Accept-Encoding', 'gzip')
    ]
}

@RMApp.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email        = request.form['email']
        password1    = request.form['password'].encode('utf-8')
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM admin WHERE correoAd=%s", [email])
        if result > 0:
            data = cur.fetchone()
            if bcrypt.hashpw(password1, data['passAd'].encode('utf-8')) == data['passAd'].encode('utf-8'):
                session["login"] = True
                session['idAd'] = data['idAd']
                session['userid'] = data['priviAd']
                session['name'] = data['nombreAd']
                attempt = session.get('attempt')
                attempt = 5
                session['attempt'] = attempt
                flash("Inicio de Sesion exitoso", 'success')
                cur.close()
                return redirect(url_for('home'))
            else:
                attempt = session.get('attempt')
                attempt = attempt - 1
                session['attempt']=attempt
                flash("Contraseña incorrecta",'danger')
                if attempt==1:
                    flash('Es tu ultimo intento, tendras que contactar a un desarrollador, Intento %d de 5' % attempt, 'error')
                else:   
                    flash('Inicio De Sesion Invalido, Intento: %d de 5'  % attempt, 'error')
        else:
            attempt = session.get('attempt')
            attempt = attempt - 1
            session['attempt']=attempt
            flash("Email incorrecto",'danger')
            if attempt==1:
                flash('Es tu ultimo intento, tendras que contactar a un desarrollador, Intento %d de 5' % attempt, 'error')
            else:   
                flash('Inicio De Sesion Invalido, Intento: %d de 5'  % attempt, 'error')
            #return redirect('/pythonlogin/')
            
    return render_template('login.html', intentos = session['attempt'])

# http://localhost:5000/home - this will be the home page, only accessible for loggedin users
@RMApp.route('/')
def home():
    session['attempt'] = 5
    # Check if user is loggedin
    if 'login' in session:
        # User is loggedin show them the home page
        return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))
  
# http://localhost:5000/logout - this will be the logout page
@RMApp.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('login', None)
   session.pop('userid', None)
   session.pop('email', None)
   session.pop('idAd', None)
   session.pop('name', None)
   # Redirect to login page
   return redirect(url_for('login'))

@RMApp.route('/index')
def index():
    # Check if user is loggedin
    if 'login' in session:
        # User is loggedin show them the home page
        return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@RMApp.route('/protected')
@login_required
def protected ():
    return "<h1>Esta es una vista protegida, solo para usuarios autenticados.</h1>"

def status_401(error):
    return redirect(url_for('login'))

def status_404(error):
    return "<h1>Pagina no encontrada </h1>", 404


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~ CRUD Administradores ~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#


#~~~~~~~~~~~~~~~~~~~ Crear Administradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/AgregarAdministrador', methods=["GET","POST"])
def agregarAdministrador():
    if 'login' in session:
        if session['userid'] == 1:
            if request.method == 'GET':
                selAdmin            =   mysql.connection.cursor()
                selAdmin.execute("SELECT * FROM admin")
                ad                  =   selAdmin.fetchall()    
                return render_template("agregarAdministrador.html", admin = ad)
            else:
                priviAd             =   int(request.form['priviAd'])
                nombreAd            =   request.form['nombreAd']
                apellidoPAd         =   request.form['apellidoPAd']
                apellidoMAd         =   request.form['apellidoMAd']
                correoAd            =   request.form['correoAd']
                telCelAd            =   request.form['telCelAd']
                telCasaAd           =   request.form['telCasaAd']
                sexoAd              =   request.form['sexoAd']
                edadAd              =   request.form['edadAd']
                passAd              =   request.form['passAd'].encode('utf-8')
                claveCifrada        =   bcrypt.hashpw(passAd,bcrypt.gensalt())
                activoAd            =   1
                regAdministrador    =   mysql.connection.cursor()
                regAdministrador.execute("INSERT INTO admin (priviAd, nombreAd, apellidoPAd, apellidoMAd, correoAd, telCelAd, telCasaAd, sexoAd, edadAd, passAd, activoAd) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",(priviAd, nombreAd, apellidoPAd, apellidoMAd, correoAd, telCelAd, telCasaAd, sexoAd, edadAd, claveCifrada, activoAd))
                mysql.connection.commit()
                admin               =   regAdministrador.lastrowid
                dia                 =   datetime.now()
                bitacora            =   mysql.connection.cursor()
                bitacora.execute("INSERT INTO altas (idAdAlta, fechaAlta) VALUES(%s, %s)", (admin, dia))
                mysql.connection.commit()
                flash('Administrador agregado con exito.')
                return redirect(url_for('verAdministrador'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))

#~~~~~~~~~~~~~~~~~~~ Ver Adminsitradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/VerAdministrador', methods=['GET', 'POST'])
def verAdministrador():
    if 'login' in session:
        if session['userid'] == 1:
            selecAdmin      =   mysql.connection.cursor()
            selecAdmin.execute("SELECT * FROM cantidadPago")
            m               =   selecAdmin.fetchall()
            selecAdmin      =   mysql.connection.cursor()
            selecAdmin.execute("SELECT COUNT(idAd) AS cuenta FROM admin WHERE activoAd IS NOT NULL")
            c               =   selecAdmin.fetchall()
            selecAdmin      =   mysql.connection.cursor()
            selecAdmin.execute("SELECT * FROM admin WHERE activoAd IS NOT NULL")
            a               =   selecAdmin.fetchall()
            return render_template('verAdministrador.html', admin = a, cuenta = c, monto = m)
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Ver Expediente Administradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/VerExpedienteAdministrador/<string:idAd>', methods=['GET', 'POST'])
def verExpAdmin(idAd):
    if 'login' in session:
        if session['userid'] == 1:
            selecAdmin      =   mysql.connection.cursor()
            selecAdmin.execute("SELECT * FROM admin WHERE idAd=%s",(idAd,))
            a               =   selecAdmin.fetchall()
            return render_template('expedienteAdmin.html', admin = a)
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ PDF Expediente Administradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/PDFExpedienteAdministrador/<string:idAd>', methods=['GET', 'POST'])
def pdfExpAdmin(idAd):
    if 'login' in session:
        if session['userid'] == 1:
            selecAdmin      =   mysql.connection.cursor()
            selecAdmin.execute("SELECT * FROM admin WHERE idAd=%s",(idAd,))
            a               =   selecAdmin.fetchall()
            selecAdmin.close()
            template            =   render_template('pdf_ExpedienteAdmin.html', admin = a)
            path_wkhtmltopdf    =   r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
            config              =   pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
            css                 =   ['static/css/bootstrap.min copy.css']
            pdf                 =   pdfkit.from_string(template, False, configuration=config, css=css)
            response            =   make_response(pdf)
            response.headers['Content-Type']          =   'aplication/pdf'
            response.headers['Content-Disposition']   =   'inline; filename = Expediente_Administrador.pdf'
            return response 
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])  
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
        

#~~~~~~~~~~~~~~~~~~~ Actualizar Administradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ActualizarAdministrador', methods=['POST'])
def actualizarAdministrador():
    if 'login' in session:
        if session['userid'] == 1:
            idAd                        =   request.form['idAd']
            priviAd                     =   int(request.form['priviAd'])
            nombreAd                    =   request.form['nombreAd']
            apellidoPAd                 =   request.form['apellidoPAd']
            apellidoMAd                 =   request.form['apellidoMAd']
            correoAd                    =   request.form['correoAd']
            telCelAd                    =   request.form['telCelAd']
            telCasaAd                   =   request.form['telCasaAd']
            sexoAd                      =   request.form['sexoAd']
            edadAd                      =   request.form['edadAd']
            actualizarAdministrador     =   mysql.connection.cursor()
            actualizarAdministrador.execute("UPDATE admin SET priviAd=%s, nombreAd=%s, apellidoPAd=%s, apellidoMAd=%s, correoAd=%s, telCelAd=%s, telCasaAd=%s, sexoAd=%s, edadAd=%s WHERE idAd=%s", (priviAd, nombreAd, apellidoPAd, apellidoMAd, correoAd, telCelAd, telCasaAd, sexoAd, edadAd, idAd,))
            mysql.connection.commit()    
            flash('Administador modificado con exito.')
            return redirect(url_for('verAdministrador'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Eliminar Administradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/EliminarAdministrador', methods=['POST'])
def eliminarAdministrador():
    if 'login' in session:
        if session['userid'] == 1:
            idAd                =   request.form['idAd']
            baja                =   None
            eliAdministrador    =   mysql.connection.cursor()
            eliAdministrador.execute("UPDATE admin SET activoAd = %s WHERE idAd = %s",(baja, idAd))
            mysql.connection.commit()
            administrador       =   request.form['idAd']
            dia                 =   datetime.now()
            bitacoraRm          =   mysql.connection.cursor()
            bitacoraRm.execute("INSERT INTO bajas (idAdBaja, fechaBaja) VALUES (%s, %s)",(administrador, dia))
            mysql.connection.commit()
            flash('Administador dado de baja con exito.')
            return redirect(url_for('verAdministradorInactivos'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Ver Adminsitradores Inactivos~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/VerAdministradoresInactivos', methods=['GET', 'POST'])
def verAdministradorInactivos():
    if 'login' in session:
        if session['userid'] == 1:
            selecResi       =   mysql.connection.cursor()
            selecResi.execute("SELECT * FROM admin WHERE activoAd IS NULL")
            a               =   selecResi.fetchall()
            selecAdmin      =   mysql.connection.cursor()
            selecAdmin.execute("SELECT COUNT(idAd) AS cuenta FROM admin WHERE activoAd IS NULL")
            c               =   selecAdmin.fetchall()
            return render_template('administradoresInactivos.html', admin = a, cuenta = c)
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Activar Administradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ActivarAdministrador', methods=['GET', 'POST'])
def activarAdministrador():
    if 'login' in session:
        if session['userid'] == 1:
            idAd                    =   request.form['idAd']
            activa                  =   1 
            activarAdministrador    =   mysql.connection.cursor()
            activarAdministrador.execute("UPDATE admin SET activoAd = %s WHERE idAd = %s", (activa, idAd))
            mysql.connection.commit()
            administrador           =   request.form['idAd']
            dia                     =   datetime.now()
            bitacoraRm              =   mysql.connection.cursor()
            bitacoraRm.execute("INSERT INTO altas (idAdAlta, fechaAlta) VALUES (%s, %s)",(administrador, dia))
            mysql.connection.commit()
            flash("Administrador activado con exito.")
            return redirect(url_for('verAdministrador'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Buscar Administradores ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/BuscarAdministrador', methods=['GET', 'POST'])
def buscarAdministrador():
    if 'login' in session:
        if session['userid'] == 1:
            busqueda         =   request.form['busqueda']
            buscarAdmin      =   mysql.connection.cursor()
            result           =   buscarAdmin.execute("SELECT * FROM admin WHERE activoAd IS NOT NULL IS NOT NULL AND MATCH (nombreAd, apellidoPAd, apellidoMAd) AGAINST ('+"+ busqueda +"')")
            a                =   buscarAdmin.fetchall()
            if result > 0:
                return render_template('resultadoAdminBusqueda.html', admin = a)
            else:
                flash("El Adminitrador no existe.")
                return redirect(url_for('verAdministrador'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Actualizar Monto de Pago ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ActualizarMontoPago', methods=['POST'])
def actualizarMonto():
    if 'login' in session:
        if session['userid'] == 1:
            idCantidadPago              =   request.form['idCantidadPago']
            idAdCP                      =   request.form['idAdCP']
            antiguoMonto                =   request.form['antiguoMonto']
            nuevoMonto                  =   request.form['nuevoMonto']
            dia                         =   datetime.now()
            actualizarMontoPago         =   mysql.connection.cursor()
            actualizarMontoPago.execute("UPDATE cantidadPago SET idCantidadPago=%s, idAdCP=%s, antiguoMonto=%s, nuevoMonto=%s, fechaCP=%s WHERE idCantidadPago=%s", (idCantidadPago, idAdCP, antiguoMonto, nuevoMonto, dia))
            mysql.connection.commit()    
            flash('Monto de pago modificado con exito.')
            return redirect(url_for('verAdministrador'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))

#~~~~~~~~~~~~~~~~~~~ Cambiar Contra ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/CambiarContra', methods=['GET','POST'])
def passAdmin():
    if 'login' in session:
        if session['userid'] == 1:
            idAd            =   request.form['idAd']
            passAd          =   request.form['passAd'].encode('utf-8')
            ClaveCifrada    =   bcrypt.hashpw(passAd, bcrypt.gensalt())
            upAdministradorC =   mysql.connection.cursor()
            upAdministradorC.execute("UPDATE admin SET passAd=%s WHERE idAd=%s", (ClaveCifrada, idAd))
            flash('Cambio de Contraseña Exitoso')
            mysql.connection.commit()
            return redirect(url_for('verAdministrador'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~ CRUD Residentes ~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#


#~~~~~~~~~~~~~~~~~~~ Crear Residentes ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/AgregarResidente', methods=["GET","POST"])
def AgregarResidente():
    
    if 'login' in session:
        if session['userid'] == 1 or session['userid'] == 2:
            if request.method == 'GET':
                selAdmin = mysql.connection.cursor()
                selAdmin.execute("SELECT * FROM admin")
                ad           =   selAdmin.fetchall()    
                return render_template("agregarResidente.html", admin=ad)
            else:
                idAd                =   session['idAd']
                nombreRe            =   request.form['nombreRe']
                apellidoPRe         =   request.form['apellidoPRe']
                apellidoMRe         =   request.form['apellidoMRe']
                sexoRe              =   request.form['sexoRe']
                edadRe              =   request.form['edadRe']
                telCasaRe           =   request.form['telCasaRe']
                telCelRe            =   request.form['telCelRe']
                estadoRe            =   request.form['estadoRe']
                municipioRe         =   request.form['municipioRe']
                calleRe             =   request.form['calleRe']
                numExtRe            =   request.form['numExtRe']
                cpRe                =   request.form['cpRe']
                entreCalle1         =   request.form['calle1']
                entreCalle2         =   request.form['calle2']
                activoRe            =   1

                regResidente        =   mysql.connection.cursor()
                regResidente.execute("INSERT INTO residente (idAdRe, nombreRe, apellidoPRe, apellidoMRe, sexoRe, edadRe, telCasaRe, telCelRe, estadoRe, municipioRe, calleRe, numExtRe, cpRe, entreCalle1, entreCalle2, activoRe) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",(idAd, nombreRe, apellidoPRe, apellidoMRe, sexoRe, edadRe, telCasaRe, telCelRe, estadoRe, municipioRe, calleRe, numExtRe, cpRe, entreCalle1, entreCalle2, activoRe))
                mysql.connection.commit()
                resi                =   regResidente.lastrowid
                dia                 =   datetime.now()
                bitacora            =   mysql.connection.cursor()
                bitacora.execute("INSERT INTO altas (idAdAlta, idReAlta, fechaAlta) VALUES(%s, %s, %s)", (idAd, resi, dia))
                mysql.connection.commit()
                flash('Residente agregado con exito.')
                return redirect(url_for('verResidente'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
       
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Ver Residentes ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/VerResidente', methods=['GET', 'POST'])
def verResidente():
    if 'login' in session:
        selecResi       =   mysql.connection.cursor()
        selecResi.execute("SELECT COUNT(idRe) AS cuenta FROM residente WHERE activoRe IS NOT NULL")
        c               =   selecResi.fetchall()
        selecResi       =   mysql.connection.cursor()
        selecResi.execute("SELECT * FROM residente WHERE activoRe IS NOT NULL")
        r               =   selecResi.fetchall()
        selecResi       =   mysql.connection.cursor()
        selecResi.execute("SELECT * FROM cantidadpago")
        m               =   selecResi.fetchall()
        return render_template('verResidente.html', residente = r, cuenta = c, monto = m)
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Ver Expediente Residentes ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/VerExpedienteResidente/<string:idRe>', methods=['GET', 'POST'])
def verExpResi(idRe):
    if 'login' in session:
        selecResi       =   mysql.connection.cursor()
        selecResi.execute("SELECT * FROM residente WHERE idRe=%s",(idRe,))
        r               =   selecResi.fetchall()
        return render_template('expedienteResi.html', residente = r)
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ PDF Expediente Residentes ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/PDFExpedienteResidente/<string:idRe>', methods=['GET', 'POST'])
def pdfExpResi(idRe):
    if 'login' in session:
        selecResi       =   mysql.connection.cursor()
        selecResi.execute("SELECT * FROM residente WHERE idRe=%s",(idRe,))
        r               =   selecResi.fetchall()
        selecResi.close()
        template            =   render_template('pdf_ExpedienteResi.html', residente = r)
        path_wkhtmltopdf    =   r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
        config              =   pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
        css                 =   ['static/css/bootstrap.min copy.css']
        pdf                 =   pdfkit.from_string(template, False, configuration=config, css=css)
        response            =   make_response(pdf)
        response.headers['Content-Type']          =   'aplication/pdf'
        response.headers['Content-Disposition']   =   'inline; filename = Expediente.pdf'        
        return response
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Actualizar Residentes ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ActualizarResidente', methods=['POST'])
def actualizarResidente():
    if 'login' in session:
        if session['userid'] == 1 or session['userid'] == 2:
            idRe                =   request.form['idRe']
            nombreRe            =   request.form['nombreRe']
            apellidoPRe         =   request.form['apellidoPRe']
            apellidoMRe         =   request.form['apellidoMRe']
            sexoRe              =   request.form['sexoRe']
            edadRe              =   request.form['edadRe']
            telCasaRe           =   request.form['telCasaRe']
            telCelRe            =   request.form['telCelRe']
            estadoRe            =   request.form['estadoRe']
            municipioRe         =   request.form['municipioRe']
            calleRe             =   request.form['calleRe']
            numExtRe            =   request.form['numExtRe']
            cpRe                =   request.form['cpRe']
            entreCalle1         =   request.form['calle1']
            entreCalle2         =   request.form['calle2']
            actualizarResidente = mysql.connection.cursor()
            actualizarResidente.execute("UPDATE residente SET nombreRe=%s, apellidoPRe=%s, apellidoMRe=%s, sexoRe=%s, edadRe=%s, telCasaRe=%s, telCelRe=%s, estadoRe=%s, municipioRe=%s, calleRe=%s, numExtRe=%s, cpRe=%s, entreCalle1=%s, entreCalle2=%s WHERE idRe=%s", (nombreRe, apellidoPRe, apellidoMRe, sexoRe, edadRe, telCasaRe, telCelRe, estadoRe, municipioRe, calleRe, numExtRe, cpRe, entreCalle1, entreCalle2, idRe,))
            mysql.connection.commit()    
            flash('Residente modificado con exito.')
            return redirect(url_for('verResidente'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
        
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Eliminar Residentes ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/EliminarResidente', methods=['POST'])
def eliminarResidente():
    if 'login' in session:
        if session['userid'] == 1 or session['userid'] == 2:
            idAd            =   session['idAd']
            idRe            =   request.form['idRe']
            baja            =   None
            eliResidente    =   mysql.connection.cursor()
            eliResidente.execute("UPDATE residente SET activoRe = %s WHERE idRe = %s",(baja, idRe))
            mysql.connection.commit()
            residente       =   request.form['idRe']
            dia             =   datetime.now()
            bitacoraRm      =   mysql.connection.cursor()
            bitacoraRm.execute("INSERT INTO bajas (idAdBaja, idReBaja, fechaBaja) VALUES (%s, %s, %s)",(idAd, residente, dia))
            mysql.connection.commit()
            flash('Residente dado de baja con exito.')
            return redirect(url_for('verResidenteInactivos'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
        
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~ Ver Residentes Inactivos ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/VerResidentesInactivos', methods=['GET', 'POST'])
def verResidenteInactivos():
    if 'login' in session:
        selecResi       =   mysql.connection.cursor()
        selecResi.execute("SELECT * FROM residente WHERE activoRe IS NULL")
        r               =   selecResi.fetchall()
        selecResi       =   mysql.connection.cursor()
        selecResi.execute("SELECT COUNT(idRe) AS cuenta FROM residente WHERE activoRe IS NULL")
        c               =   selecResi.fetchall()
        return render_template('listaInactivos.html', residente = r, cuenta = c)
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
   

#~~~~~~~~~~~~~~~~~~~ Activar Residentes ~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ActivarResidente', methods=['GET', 'POST'])
def activarResidente():
    if 'login' in session:
        if session['userid'] == 1 or session['userid'] == 2:
            idRe                =   request.form['idRe']
            activa              =   1 
            activarResidente    =   mysql.connection.cursor()
            activarResidente.execute("UPDATE residente SET activoRe = %s WHERE idRe = %s", (activa, idRe))
            mysql.connection.commit()
            residente           =   request.form['idRe']
            dia                 =   datetime.now()
            bitacoraRm          =   mysql.connection.cursor()
            bitacoraRm.execute("INSERT INTO altas (idReAlta, fechaAlta) VALUES (%s, %s)",(residente, dia))
            mysql.connection.commit()
            flash("Residente activado con exito.")
            return redirect(url_for('verResidente'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
        
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~~~ Buscar Residentes ~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/BuscarResidente', methods=['GET', 'POST'])
def buscarResidente():
    if 'login' in session:
        busqueda         =   request.form['busqueda']
        buscarResi       =   mysql.connection.cursor()
        result           =   buscarResi.execute("SELECT * FROM residente WHERE activoRe IS NOT NULL AND MATCH (nombreRe, apellidoPRe, apellidoMRe) AGAINST ('+"+ busqueda +"')")
        r = buscarResi.fetchall()
        if result > 0:
            return render_template('resultadoResiBusqueda.html', residente = r)
        else:
            flash("El Residente no existe.")
            return redirect(url_for('verResidente'))
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
   



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~ CRUD Pagos ~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~ Agregar Pago ~~~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/AgregarPago', methods=["GET","POST"])
def agregarPago():
    if 'login' in session:
        if session['userid'] == 1 or session['userid'] == 2:
            if request.method == 'POST':
                year                    =   datetime.today().year
                month                   =   datetime.today().month
                residente               =   request.form['idRe']
                selecResi               =   mysql.connection.cursor()
                selecResi.execute("SELECT EXTRACT(YEAR FROM fechaPagos) AS anio FROM residente R INNER JOIN pagos P ON R.idRe = P.idRePagos WHERE activoRe IS NOT NULL AND idRe=%s",(residente,))
                y                       =   selecResi.fetchone()
                residente               =   request.form['idRe']
                selecResi               =   mysql.connection.cursor()
                selecResi.execute("SELECT EXTRACT(MONTH FROM fechaPagos) AS mes FROM residente R INNER JOIN pagos P ON R.idRe = P.idRePagos WHERE activoRe IS NOT NULL AND idRe=%s",(residente,))
                m                       =   selecResi.fetchone()

                if y == None and m == None:
                    idAd                =   session['idAd']
                    idRe                =   request.form['idRe']
                    montoPagos          =   int(request.form['monto'])
                    descPa              =   request.form['descPa']
                    metodoPa            =   request.form['metodoPa']
                    nombrePPa           =   request.form['nombrePPa']
                    fechaPagos          =   datetime.now()
                    hora                =   datetime.now().time()
                    regPago             =   mysql.connection.cursor()
                    regPago.execute("INSERT INTO pagos (idAdPagos, idRePagos, montoPagos, descPa, metodoPa, nombrePPa, fechaPagos, horaPagos) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",(idAd, idRe, montoPagos, descPa, metodoPa, nombrePPa, fechaPagos, hora))
                    mysql.connection.commit()
                    flash('Pago agregado con exito.')
                    idPa               =   regPago.lastrowid
                    print(idPa)
                    reciboPago(idPa)
                    print("Holaaa Vacio")
                    return redirect(url_for('verPagos'))

                elif y.get('anio') == year and m.get('mes') == month:
                    flash('Ya se realizo el pago de ese mes.')
                    return redirect(url_for('verResidente'))

                else:
                    idAd                =   session['idAd']
                    idRe                =   request.form['idRe']
                    montoPagos          =   int(request.form['monto'])
                    descPa              =   request.form['descPa']
                    metodoPa            =   request.form['metodoPa']
                    nombrePPa           =   request.form['nombrePPa']
                    fechaPagos          =   datetime.now()
                    hora                =   datetime.now().time()
                    regPago             =   mysql.connection.cursor()
                    regPago.execute("INSERT INTO pagos (idAdPagos, idRePagos, montoPagos, descPa, metodoPa, nombrePPa, fechaPagos, horaPagos) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",(idAd, idRe, montoPagos, descPa, metodoPa, nombrePPa, fechaPagos, hora))
                    mysql.connection.commit()
                    flash('Pago agregado con exito.')
                    idPa               =   regPago.lastrowid
                    redirect(url_for(reciboPago(idPa)))
                    print("Holaaa Lleno")
                    return redirect(url_for('verPagos'))
            else:
                return redirect(url_for('verResidente'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
        
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~~~~~~ Ver Pagos ~~~~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ReciboPago/<string:idPa>', methods=['GET', 'POST'])
def reciboPago(idPa):
    if 'login' in session:
        selecPago           =   mysql.connection.cursor()
        selecPago.execute("SELECT * FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe WHERE idPa=%s",(idPa,))
        p                   =   selecPago.fetchall()

        selecPago           =   mysql.connection.cursor()
        selecPago.execute("SELECT EXTRACT(YEAR FROM fechaPagos) AS year FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe WHERE idPa=%s",(idPa,))
        y                   =   selecPago.fetchone()
        year = y.get('year')
        year = str(year)

        selecPago           =   mysql.connection.cursor()
        selecPago.execute("SELECT EXTRACT(MONTH FROM fechaPagos) AS month FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe")
        m                   =   selecPago.fetchone()
        if m.get('month') == 1:
            mes = 'Enero'
        elif m.get('month') == 2:
            mes = 'Febrero'
        elif m.get('month') == 3:
            mes = 'Marzo'
        elif m.get('month') == 4:
            mes = 'Abril'
        elif m.get('month') == 5:
            mes = 'Mayo'
        elif m.get('month') == 6:
            mes = 'Junio'
        elif m.get('month') == 7:
            mes = 'Julio'
        elif m.get('month') == 8:
            mes = 'Agosto'
        elif m.get('month') == 9:
            mes = 'Septiembre'
        elif m.get('month') == 10:
            mes = 'Octubre'
        elif m.get('month') == 11:
            mes = 'Noviembre'
        else:
            mes = 'Diciembre'

        selecPago           =   mysql.connection.cursor()
        selecPago.execute("SELECT EXTRACT(DAY FROM fechaPagos) AS dia FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe WHERE idPa=%s",(idPa,))
        d                   =   selecPago.fetchone()
        dia = d.get('dia')
        dia = str(dia)
        
        selecPago.close()
        template            =   render_template('pdf_ReciboPago.html', pago = p, year = year, month = mes, day = dia)
        path_wkhtmltopdf    =   r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
        config              =   pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
        css                 =   ['static/css/bootstrap.min copy.css']
        pdf                 =   pdfkit.from_string(template, False, configuration=config, css=css)
        response            =   make_response(pdf)
        response.headers['Content-Type']          =   'aplication/pdf'
        response.headers['Content-Disposition']   =   'inline; filename = Recibo.pdf'        
        return response
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~~~~~~ Ver Pagos ~~~~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/VerPagos', methods=['GET', 'POST'])
def verPagos():
    if 'login' in session:
        selecPago       =   mysql.connection.cursor()
        selecPago.execute("SELECT * FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe ORDER BY idPa DESC")
        p               =   selecPago.fetchall()
        selecMonto      =   mysql.connection.cursor()
        selecMonto.execute("SELECT * FROM cantidadpago")
        cp              =   selecMonto.fetchall()
        return render_template('verPagos.html', pagos = p, cp =cp)
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    
#~~~~~~~~~~~~~~~~~~~~~~~~ Actualizar Monto ~~~~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ActualizarMonto', methods=['GET', 'POST'])
def actualizarMon():
    if 'login' in session:
        if session['userid'] == 1:
            idCantidadPago  =   2
            antiguoMonto    =   request.form['antiguoMonto']
            nuevoMonto      =   request.form['nuevoMonto']
            fechaCP         =   datetime.now()
            selecMonto      =   mysql.connection.cursor()
            selecMonto.execute("UPDATE cantidadpago SET antiguoMonto=%s, nuevoMonto=%s, fechaCP=%s WHERE idCantidadPago=%s",(antiguoMonto, nuevoMonto, fechaCP, idCantidadPago))
            mysql.connection.commit()
            flash('Monto Actualizado con Exito')
            return redirect(url_for('verPagos'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))

#~~~~~~~~~~~~~~~~~~~~~~~~ Actualizar Pagos ~~~~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/ActualizarPago', methods=['POST'])
def actualizarPago():
    if 'login' in session:
        if session['userid'] == 1:
            descPa                      =   request.form['descPa']
            metodoPa                    =   request.form['metodoPa']
            nombrePPa                   =   request.form['nombrePPa']
            actualizarPago              =   mysql.connection.cursor()
            actualizarPago.execute("UPDATE pagos SET descPa=%s, metodoPa=%s, nombrePPa=%s WHERE idPa=%s", (descPa, metodoPa, nombrePPa))
            mysql.connection.commit()    
            flash('Pago modificado con exito.')
            return redirect(url_for('verPagos'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
    
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~~~~~~ Eliminar Pagos ~~~~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/EliminarPago', methods=['POST'])
def eliminarPago():
    if 'login' in session:
        if session['userid'] == 1 or session['userid'] == 2:
            idPa         =  request.form['idPa']
            eliPago      =  mysql.connection.cursor()
            eliPago.execute("DELETE FROM pagos WHERE idPa = %s",(idPa,))
            mysql.connection.commit()
            flash('Pago eliminado con exito.')
            return redirect(url_for('verPagos'))
        else:
            flash('No Tienes Permisos Para Ingresar A Esta Pagina')
            return render_template('index.html', username=session['name'], role=session['userid'])
        
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

#~~~~~~~~~~~~~~~~~~~~~~~~ Buscar Pagos ~~~~~~~~~~~~~~~~~~~~~~~~#  FALTA PROBAR
@RMApp.route('/BuscarPagos', methods=['GET', 'POST'])
def buscarPagos():
    if 'login' in session:
        busqueda         =   request.form['busqueda']
        buscarPago       =   mysql.connection.cursor()
        buscarPago.execute("SELECT * FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe AND MATCH (nombreRe, apellidoPRe, apellidoMRe) AGAINST ('+"+ busqueda +"')")
        p                =   buscarPago.fetchall()
        
        print(p)

        if p == ():
            buscarPago       =   mysql.connection.cursor()
            buscarPago.execute("SELECT * FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe AND MATCH (calleRe) AGAINST ('+"+ busqueda +"')")
            p                =   buscarPago.fetchall()

            if p == ():
                buscarPago       =   mysql.connection.cursor()
                buscarPago.execute("SELECT * FROM pagos P INNER JOIN admin A ON P.idAdPagos = A.idAd INNER JOIN residente R ON P.idRePagos = R.idRe AND MATCH (calleRe) AGAINST ('+"+ busqueda +"')")
                p                =   buscarPago.fetchall()

                if p == ():
                    flash('No se encontraron resultados.')
                    return redirect(url_for('verPagos'))

                else:
                    return render_template('resultadoPagoBusqueda.html', pagos = p)

            else:
                return render_template('resultadoPagoBusqueda.html', pagos = p)
        else:
            return render_template('resultadoPagoBusqueda.html', pagos = p)
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    


#~~~~~~~~~~~~~~~~~~~~~~~~ Historail Pagos ~~~~~~~~~~~~~~~~~~~~~~~~#
@RMApp.route('/HistorialPagos/<string:idRe>', methods=['GET', 'POST'])
def verHistorialPagos(idRe):
    if 'login' in session:
        selecHP             =   mysql.connection.cursor()
        selecHP.execute("SELECT * FROM residente R INNER JOIN pagos P ON R.idRe = P.idRePagos INNER JOIN admin A ON P.idAdPagos = A.idAd WHERE idRe=%s ORDER BY fechaPagos DESC",(idRe,))
        hp                   =   selecHP.fetchall()
        if hp == ():
            flash('No tiene pagos registrados')
            return redirect(url_for('index'))
        else:
            return render_template('historialPagos.html', hp = hp)
    if session['attempt'] >= 1:
        return redirect(url_for('login'))
    return redirect(url_for('login'))
    

if __name__ == '__main__':
    RMApp.secret_key = '123'
    csrf.init_app(RMApp)
    RMApp.register_error_handler(401,status_401)
    RMApp.register_error_handler(404,status_404)
    RMApp.run(port=3000,debug=True)


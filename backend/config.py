from flask import Flask
from flask_mail import Mail #para enviar email

app = Flask(__name__)

#para poder mandar email
mail = Mail(app)
app.config['MAIL_SERVER']="webdomain01.dnscpanel.com" 
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = "test@watermark-ubi.pt"
app.config['MAIL_PASSWORD'] = "Milan_115!"
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app) #Creating Flask-Mail instance

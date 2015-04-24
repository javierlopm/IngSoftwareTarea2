# -*- coding: utf-8 -*-. 
'''
Created on 24/9/2014

@author: Jean Carlos
'''
import uuid
import hashlib
import re
 
class clsAccessControl(object):
    def __init__(self):
        ohast=''
        
    def encript(self, value):
        # Verificar la longitud del password
        oHash=""
        olength_password=self.length_password(value)
        
                
        #Verificar el contenido del password con expresiones regulares
        hayNumero   = re.match(".*\d.*",value)        
        hayMinuscula= re.match(".*((?![_0-9A-ZÑÁÉÍÓÚ])\w).*",value)
        hayMayuscula= re.match(".*[A-ZÑÁÉÍÓÚ].*", value)
        hayCharEsp  = re.match(".*[\@\.\#\$\+\*].*",value)  
        soloValidos = re.match("((?![\_])(\w)|[\@\.\#\$\+\*])*",value)
        
        contenidoValido = (
                           (hayNumero   != None) and 
                           (hayMinuscula!= None) and 
                           (hayCharEsp  != None) and
                           (hayMayuscula!= None) and
                           (soloValidos != None)
                           )
        
        if olength_password>=8 and olength_password<=16 and contenidoValido:
            # uuid es usado para generar numeros random
            salt = uuid.uuid4().hex
            # hash
            oHash= hashlib.sha256(salt.encode() + value.encode()).hexdigest() + ':' + salt
        else:
            print('El Password debe contener entre 8 y 16 caracteres')
        return oHash   
    
    def check_password(self, oPassworkEncript, oCheckPassword):
        # Verificar la longitud del password
        olength_password=self.length_password(oCheckPassword)
        if olength_password>=8 and olength_password<=16 and oPassworkEncript!="": 
            # uuid es usado para generar numeros random
            oPassworkEncript, salt = oPassworkEncript.split(':')
            return oPassworkEncript == hashlib.sha256(salt.encode() + oCheckPassword.encode()).hexdigest()
        else:
            print('El Password no posee la cantidad de caracteres requerida')
            return False
    
    def length_password(self, user_password):
        # uuid es usado para generar numeros random
        return len(user_password)

#Verificacion de archivo principal para poder correr las pruebas unitarias
if __name__ == "__main__":
    #Para encriptar un passwork  
    oPassword = input('Por favor ingrese su password: ')
    #Se crea un objeto tipo clsAccessControl
    oAccessControl=clsAccessControl()
    oPassworkEncript = oAccessControl.encript(oPassword)
    print('El Password almacenado en la memoria es: ' + oPassworkEncript)
    if oPassworkEncript:
        #Para validar el passwork introducido
        oCheckPassword = input('Para verificar su password, ingreselo nuevamente: ')
        if oAccessControl.check_password(oPassworkEncript, oCheckPassword):
            print('Ha introducido el password correcto')
        else:
            print('El password es diferente')



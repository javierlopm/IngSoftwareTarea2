'''
Created on Apr 19, 2015

@authors: 
    Cristina Betancourt
    Javier Lopez
'''
import unittest
import sys
sys.path.append('..')
import mdlaccesscontrol.mdlaccesscontrol

class MdlTest(unittest.TestCase):
    
    def setUp(self):
        self.acsc=mdlaccesscontrol.mdlaccesscontrol.clsAccessControl()
    
    """Casos Frontera"""
    
    #Verificar tamano cero
    def testLongCero(self):
        self.assertEqual(0, self.acsc.length_password(""), "Error! tamano de la clave invalido")
    
    #Verificar tamano 7
    def testlongSiete(self):
        self.assertEqual("", self.acsc.length_password("@!@!@!@"), "Error! tamano de la clave invalido")
        
    #Verificar tamano 8
    def testlongOcho(self):
        self.assertEqual("", self.acsc.length_password("abrrdrhs"), "Error! tamano de la clave invalido")
        
    #Verificar tamano 16
    def testLongDieciseis(self):
        self.assertEqual(16, self.acsc.length_password("1234567891230789"), "Error! tamano de la clave invalido")
        
     #Verificar tamano 17
    def testLongDiecisiete(self):
        self.assertEqual(17, self.acsc.length_password("123456789a1230789"), "Error! tamano de la clave invalido")
        
    #Verificar tamano 2^32-1
    def testLongGrande(self):
        clave = "a"
        for i in range(1,2**31-1):
            clave = clave + "a"
        self.assertEqual(2**31-1, self.acsc.length_password(clave), "Error! tamano de la clave invalido")
    
    #Caso sin numeros
    def testNoNum(self):
        self.assertEqual("", self.acsc.encript("a@b$C$d$Oe"), "Error$ La clave sin numeros se encripto$")
    
    #Caso sin letras
    def testNoChars(self):
        self.assertEqual("", self.acsc.encript("8#3+@#8$6$4"), "Error$ La clave sin letras fue encriptada$")
        
    #Caso sin caracteres especiales
    def testNoEspecialChars(self):
        self.assertEqual("", self.acsc.encript("aBcde12345"), "Error$ La clave sin caracteres especiales fue encriptada$")
    
    #Caso sin letas mayusculas
    def testNoMayus(self):
        self.assertEqual("", self.acsc.encript("acei256#@"), "Error$ la clave sin mayusculas fue encriptada")
    
    #Caso de string largo fuera del limite superior
    def testLargoNoEncript(self):
        self.assertEqual("",self.acsc.encript("12c45f78i$k2@4567"),"Error$ se encripto cuando no debia$")
    
    #Caso de string largo en el limite superior
    def testLargoEncript(self):
        self.assertNotEqual("", self.acsc.encript("12c5F78i$k2@4567"), "Error$ clave no encriptada")
    
    #Caso de string largo dentro del limite superior
    def testLargoSiEncript(self):
        self.assertNotEqual("", self.acsc.encript("12c5F78i$k2@456"), "Error$ clave no encriptada")
        
    #Caso de string corto, fuera del limite inferior por un caracter
    def testCortoNoEncript(self):
        self.assertEqual("",self.acsc.encript("@2c$5f7"),"Error$ se encripto cuando no debia$")
        
    #Caso de string corto, en el limite inferior
    def testCortoEncript(self):
        self.assertNotEqual("",self.acsc.encript("@2c*5f7I"),"Error$ clave no encriptada$")
        
    #Caso de string corto, dentro del limite inferior
    def testCortoSiEncript(self):
        self.assertNotEqual("",self.acsc.encript("@2c*5f78I"),"Error$ clave no encriptada$")
        
    #Prueba de codificacion utf-8 clave con caracteres latinos
    def testEnie(self):
        self.assertNotEqual("",self.acsc.encript("ñ4oáóTí@úT"),"Error$ clave no encriptada$")
                     
    #Caso verificacion con un caracter menos
    def testVerifCharMenos(self):
        claveCifrada = self.acsc.encript("abC4d12$@")
        self.assertFalse(self.acsc.check_password(claveCifrada,"aC4d12$@"), "Error$ Verificacion no valida$")
        
    #Caso verificacion con un caracter mas
    def testVerifCharMas(self):
        claveCifrada = self.acsc.encript("fgC4d12$@")
        self.assertFalse(self.acsc.check_password(claveCifrada,"afgC4d12$@"), "Error$ Verificacion no valida$")
    
    #Caso verificacion con un caracter distinto
    def testVerifCharDist(self):
        claveCifrada = self.acsc.encript("fv$ueF13di+")
        self.assertFalse(self.acsc.check_password(claveCifrada,"fv$ueF13hi-"), "Error$ Verificacion no valida$")
        
    #Caso verificacion valida
    def testVerifValida(self):
        claveCifrada = self.acsc.encript("eGe123f@*fe")
        self.assertTrue(self.acsc.check_password(claveCifrada,"eGe123f@*fe"), "Error$ Verificacion valida$")
    
    """Casos esquina"""
    
    #Caso sin numeros y dentro del limite inferior
    def testCortoNoNums(self):
        self.assertEqual("", self.acsc.encript("aiB@*$cd"), "Error$ Clave no encriptda por error$")
        
    #Caso sin letras y fuera del limite superior
    def testLargoNoChar(self):
        self.assertEqual("", self.acsc.encript("1234@$+836232133$"), "Error$ Clave no encriptada$")
    
    #Caso dentro del limite superior y sin letras
    def testCasiLargoNochar(self):
        self.assertEqual("", self.acsc.encript("1234@$+836232133"), "Error$ Encriptada sin tener letras$")
        
    #Verificacion distinta por un caracter de mas y fuera del limite superior
    def testVerifLargaCharMas(self): 
        claveCifrada = self.acsc.encript("aru$@f3853FI@-9t")
        self.assertFalse(self.acsc.check_password(claveCifrada,"aru$@f3853FI@-9ty"), "Error$ Verificacion no valida$")
    
    #Verificacion distinta por un caracter de menos y fuera del limite inferior
    def testVerifCortaCharMenos(self):
        claveCifrada = self.acsc.encript("dER5643@")
        self.assertFalse(self.acsc.check_password(claveCifrada,"dER643@"), "Error$ Verificacion no valida$")
    
    #Verificacion de dos strings sin caracteres especiales con longitud valida
    def testEquivNoEsp(self):
        claveCifrada = self.acsc.encript("a6jLy5h4")
        self.assertFalse(self.acsc.check_password(claveCifrada,"a6jLy5h4"),"Error$ Encriptados indebidamente")
    
    """Pruebas maliciosas"""
    
    #Caso de string vacio
    def testCadenaNula(self):
        self.assertEqual("",self.acsc.encript(""), "Error$ se obtuvo una encriptacion")
        
    #Caso verificacion vacia
    def testVerifVacia(self):
        claveCifrada = self.acsc.encript("abC4d12$@")
        self.assertFalse(self.acsc.check_password(claveCifrada,""), "Error$ Verificacion no valida$")
    
    #Intento de cierre de comilla + extremo de validez, posible entrada para sqlInyections
    def testIntentoVacio(self):
        string = "\"DROP TABLE USER"
        self.assertNotEqual(string,self.acsc.encript(string),"El string entro al sistema sin ser encriptado")
        self.assertEqual("",self.acsc.encript(string),"String fue encriptado en situacion invalida")
    
    #String con caracteres de control no presentes en el teclado
    def testCharNoImp(self):
        string = "\1a\2D\1*Tp$3" #String longitud 10
        self.assertEqual("", self.acsc.encript(string) ,"String con caracteres inesperados encriptado por error")
        
    
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

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
    #Caso sin numeros
    def testNoNum(self):
        self.assertEqual("", self.acsc.encript("a@b!C-d$Oe"), "Error! La clave sin numeros se encripto!")
    
    #Caso sin letras
    def testNoChars(self):
        self.assertEqual("", self.acsc.encript("8#3-_-8$6!4"), "Error! La clave sin letras fue encriptada!")
        
    #Caso sin caracteres especiales
    def testNoEspecialChars(self):
        self.assertEqual("", self.acsc.encript("aBcde12345"), "Error! La clave sin caracteres especiales fue encriptada!")
    
    #Caso sin letas mayusculas
    def testNoMayus(self):
        self.assertEqual("", self.acsc.encript("acei256#@"), "Error! la clave sin mayusculas fue encriptada")
    
    #Caso de string largo fuera del limite superior
    def testLargoNoEncript(self):
        self.assertEqual("",self.acsc.encript("12c45f78i!k2@4567"),"Error! se encripto cuando no debia!")
    
    #Caso de string largo dentro del limite superior
    def testLargoEncript(self):
        self.assertNotEqual("", self.acsc.encript("12c45f78i!k2@456"), "Error! clave no encriptada")
    
    #Caso de string corto, fuera del limite inferior por un caracter
    def testCortoNoEncript(self):
        self.assertEqual("",self.acsc.encript("@2c!5f7"),"Error! se encripto cuando no debia!")
        
    #Caso de string corto, dentro del limite inferior
    def testCortoEncript(self):
        self.assertNotEqual("",self.acsc.encript("@2c!5f7I"),"Error! clave no encriptada!")
        
    #Prueba de codificacion utf-8 clave con caracteres latinos
    def testEnie(self):
        self.assertNotEqual("",self.acsc.encript("ñ4oáóTí@úT"),"Error! clave no encriptada!")
    
    #Caso de string vacio
    def testCadenaNula(self):
        self.assertEqual("",self.acsc.encript(""), "Error! se obtuvo una encriptacion")
        
    #Caso verificacion vacia
    def testVerifVacia(self):
        self.assertEqual("",self.acsc.check_password("abC4d12!@",""), "Error! Verificacion no valida!")
        
    #Caso verificacion con un caracter menos
    def testVerifCharMenos(self):
        self.assertEqual("",self.acsc.check_password("abC4d12!@","aC4d12!@"), "Error! Verificacion no valida!")
        
    #Caso verificacion con un caracter mas
    def testVerifCharMas(self):
        self.assertEqual("",self.acsc.check_password("fgC4d12!@","afgC4d12!@"), "Error! Verificacion no valida!")
    
    #Caso verificacion con un caracter distinto
    def testVerifCharDist(self):
        self.assertEqual("",self.acsc.check_password("fv!ueF13di-","fv!ueF13hi-"), "Error! Verificacion no valida!")
    
    #Caso verificacion valida
    def testVerifValida(self):
        self.assertEqual("",self.acsc.check_password("eGe123f!!fe","eGe123f!!fe"), "Error! Verificacion valida!")
    
    
    """Casos esquina"""
    
    #Caso sin numeros y dentro del limite inferior
    def testCortoNoNums(self):
        self.assertEqual("", self.acsc.encript("aib@!-cd"), "Error! Clave no encriptada!")
        
    #Caso sin letras y fuera del limite superior
    def testLargoNoChar(self):
        self.assertEqual("", self.acsc.encript("1234@!-836232133!"), "Error! Clave no encriptada!")
            
    #Verificacion distinta por un caracter de mas y fuera del limite superior
    def testVerifLargaCharMas(self):
        self.assertEqual("",self.acsc.check_password("aru!@f3853FI@-9t","aru!@f3853FI@-9ty"), "Error! Verificacion no valida!")
    
    #Verificacion distinta por un caracter de menos y fuera del limite inferior
    def testVerifCortaCharMenos(self):
        self.assertEqual("",self.acsc.check_password("dER5643@","dER643@"), "Error! Verificacion no valida!")
    
    
    """Pruebas maliciosa"""


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

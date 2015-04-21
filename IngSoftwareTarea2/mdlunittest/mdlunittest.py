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
        self.assertEqual("", self.acsc.encript("a@b!c-d$Oe"), "Error! la clave sin numeros se encripto!")
    
    #Caso sin letras
    def testNoChars(self):
        self.assertEqual("", self.acsc.encript("8#3-_-8$6!4"), "Error! la clave sin letras fue encriptada!")
    
    #Caso de string largo fuera del limite
    def testLargoNoEncript(self):
        self.assertEqual("",self.acsc.encript("12c45f78i!k2@4567"),"Error! se encripto cuando no debia!")
    
    #Caso de string largo dentro del limite
    def testLargoEncript(self):
        self.assertNotEqual("", self.acsc.encript("12c45f78i!k2@456"), "Error! clave no encriptada")
    
    #Caso de string corto, fuera del limite inferior por un caracter
    def testCortoNoEncript(self):
        self.assertEqual("",self.acsc.encript("@2c!5f7"),"Error! se encripto cuando no debia!")
        
    #Caso de string corto, cerca del limite inferior por un caracter
    def testCortoEncript(self):
        self.assertNotEqual("",self.acsc.encript("@2c!5f7I"),"Error! clave no encriptada!")
        
    #Prueba de codificacion utf-8 clave con caracteres latinos
    def testEnie(self):
        self.assertNotEqual("",self.acsc.encript("ñ4oáóTí@úT"),"Error! clave no encriptada!")
    
    #Caso de string vacio
    def testCadenaNula(self):
        self.assertEqual("",self.acsc.encript(""), "Error! se obtuvo una encriptacion")
    
    
    
    """Casos esquina"""
    
    """Pruebas maliciosa"""


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

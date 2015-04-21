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
    
    #Caso de string largo fuera del limite
    def testLargoNoEncript(self):
        self.assertEqual("",self.acsc.encript("12c45f78i!k2@4567"),"Error! se encripto cuando no debia!")
    
    #Caso de string largo dentro del limite
    def testLargoEncript(self):
        self.assertNotEqual("", self.acsc.encript("12c45f78i!k2@456"), "Error! clave no encriptada")
    
    
    
    """Casos esquina"""
    
    """Pruebas maliciosa"""


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

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
        self.a=mdlaccesscontrol.mdlaccesscontrol.clsAccessControl()
    

    def testCharEsp(self):
        self.assertEqual("",self.a.encript("12345678901234567"),"Error,se encripto cuando no debia!")



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

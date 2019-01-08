from unittest import  TestCase, main
from hash.sha512 import Sha512

frase = 'this is a test!'

class ShaTests(TestCase):
    

    def test_sha_512_empty(self):
        self.assertEqual(Sha512().hexdigest(),'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
        
    def test_sha_512_frase(self):
        self.assertEqual(Sha512(frase).hexdigest(), '5746df6112981b3236c15055113e14809578b42d9307f3dd21ef628cb2c78d6ca3f191c2402d94f98892729c41b4e3f97620a893cd0481a2846c9c166ed0e6de')

    def test_sha_512_frase_ten_times(self):
        self.assertEqual(Sha512(frase*10).hexdigest(), '83d57e91db26823110d7c3b387f457b71548458809227d60cf298ab19da67c6cb91f9ed34ead4b659174ac3f753ae8e99a5ebbfa0c48659fdf2445e16dadf17d')

    def test_sha_512_update(self):
        s = Sha512(frase)
        s.update(frase)

        self.assertEqual(s.hexdigest(), '7693c3358b77f120c99b964578d4f338bc29f209cc78a3ac43727e72eb7f1472ddeddfafd8288fab50d82af5d44bfbb38ccbc960d37a7fef0a719e7bda14a1ee')

    def test_sha_512_update2(self):
        s = Sha512(frase * 5)
        s.update(frase*5)
        self.assertEqual(s.hexdigest(), '83d57e91db26823110d7c3b387f457b71548458809227d60cf298ab19da67c6cb91f9ed34ead4b659174ac3f753ae8e99a5ebbfa0c48659fdf2445e16dadf17d')

if __name__ == "__main__":
    main()
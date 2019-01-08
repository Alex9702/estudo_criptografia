from unittest import  TestCase, main
from hash.sha256 import Sha256

frase = 'this is a test!'

class ShaTests(TestCase):
    

    def test_sha_256_empty(self):
        self.assertEqual(Sha256().hexdigest(), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        
    def test_sha_256_frase(self):
        self.assertEqual(Sha256(frase).hexdigest(), 'ca7f87917e4f5029f81ec74d6711f1c587dca0fe91ec82b87bb77aeb15e6566d')

    def test_sha_256_frase_ten_times(self):
        self.assertEqual(Sha256(frase*10).hexdigest(), '17c9617a9f78c2940179d58592a8109ff1f6c2173fd349ecc9060381b2e6a603')

    def test_sha_256_update(self):
        s = Sha256(frase)
        s.update(frase)
        self.assertEqual(s.hexdigest(), '4cb926cd6bbdc69567eaff4b34f2e8bd2fd2f3d393fe8589b99a33c68dfecf5a')

    def test_sha_256_update2(self):
        s = Sha256(frase * 5)
        s.update(frase*5)
        self.assertEqual(s.hexdigest(), '17c9617a9f78c2940179d58592a8109ff1f6c2173fd349ecc9060381b2e6a603')

if __name__ == "__main__":
    main()
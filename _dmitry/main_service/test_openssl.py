import unittest

import external.openssl_console as oc


class TestOpenSSLWrapper(unittest.TestCase):
    def test_start(self):
        with open('./test/data/device.csr', 'r', encoding='utf-8') as csr_file:
            csr_lines = csr_file.readlines()
            csr_file.close()

        result = oc.submit("".join(csr_lines))
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()

import unittest

from flask import Flask
from flask_testing import TestCase
from app import setup_app


class TestCSR(TestCase):
    def create_app(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        setup_app(app)
        return app

    def test_csr_update(self):
        create_response = self.client.post('/csr',
                                           json=dict(request='test', kind='wildcard'),
                                           follow_redirects=True)
        self.assertEqual(create_response.status_code, 200)
        self.assertIn('id', create_response.json)

        id = create_response.json['id']

        status = 'approved'
        update_response = self.client.patch('%s/%s' % ('/csr', id),
                                            json=dict(status=status),
                                            follow_redirects=True)
        self.assertEqual(update_response.status_code, 200)
        self.assertIn('status', update_response.json)
        self.assertEqual(update_response.json['status'], status)


if __name__ == '__main__':
    unittest.main()

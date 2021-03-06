import re
from requests.exceptions import HTTPError
import logging

from shopee import config
from shopee.session import LoginSessionAPI
from shopee.utils import shopee_hash, shopee_uuid


logger = logging.getLogger(__name__)


class ShopeeLoginSessionAPI(LoginSessionAPI):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, login_url=config.SHOPEE_LOGIN_URL, **kwargs)

    def _get_captcha_key(self):
        return shopee_uuid(hex_uuid=True)

    def _get_phone(self):
        while True:
            phone = input('Phone number (Ex. 0912345678): ')
            if re.match(r'09\d{8}', phone):
                return '886{}'.format(phone[1:])

    def _get_password_hash(self):
        password = input('Password: ')
        return shopee_hash(password)

    def _get_sms_code(self):
        return input('sms code (Ex. 082145): ')

    def fill_login_data(self, data):
        if 'captcha' not in data:
            data['captcha'] = ''
        if 'captcha_key' not in data:
            data['captcha_key'] = self._get_captcha_key()
        if 'phone' not in data:
            data['phone'] = self._get_phone()
        if 'password_hash' not in data:
            data['password_hash'] = self._get_password_hash()
        if 'remember' not in data:
            data['remember'] = True
        return data

    @property
    def login_data(self):
        data = self.login_jsonfile.load()
        data = self.fill_login_data(data)
        self.login_jsonfile.save(data)
        return data

    def login(self):
        try:
            return super().login()
        except HTTPError as e:
            if e.response.status_code != 481:
                raise
        # got 481, login again with vcode (sms code from user)
        logger.info('Login failed with error code 481')
        extra_data = {'vcode': self._get_sms_code()}
        logger.info('Trying to login again with extra_data %s', extra_data)
        res = super().login(extra_data=extra_data)
        logger.info('Second login response %s', res)
        return res


class ShopeeAPI(ShopeeLoginSessionAPI):
    def get(self, url, params=None):
        params = params or {}
        shopee_params = self._pretend(params)
        return super().get(url, params=shopee_params)

    def post(self, url, data, params=None):
        params = params or {}
        shopee_params = self._pretend(params)
        return super().post(url, data=data, params=shopee_params)

    def _pretend(self, params):
        cookies = {
            'SPC_CDS': self.sess.cookies.get('SPC_CDS', shopee_uuid()),
            'SPC_CDS_VER': self.sess.cookies.get('SPC_CDS_VER', '2'),
        }
        self.update_cookies(cookies)
        params.update(cookies)
        return params

from pathlib import Path


RESOURCE_PATH = Path(__file__).parent / 'resource'
DEFAULT_HEADER_FILE = RESOURCE_PATH / 'headers.json'
DEFAULT_COOKIES_FILE = RESOURCE_PATH / 'cookies.json'
DEFAULT_LOGIN_FILE = RESOURCE_PATH / 'login.json'
SHOPEE_LOGIN_URL = 'https://seller.shopee.tw/api/v1/login/'

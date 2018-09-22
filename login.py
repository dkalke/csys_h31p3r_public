import hashlib
import hmac
import requests
import config


class Login:

    def __init__(self, _config):
        self.server_status = None
        self.login_status = False
        self.secure_random = None
        self.init_message = None
        self.login_session = requests.session()
        self.login_config = _config

        self.student_id = None
        self.allowed_id = False

    def login_init(self):
        package = self.login_session.post(config.get_url('login'),
                                          data=config.get_payload(mode='login_init'),
                                          headers=self.login_config.headers)

        if package.status_code == 200:
            package = package.json()
            self.server_status = package['result']
            try:
                self.secure_random = package['secureRandom']
                return package
            except KeyError:
                # print(config.msg_server_begin+package['message'])
                self.init_message = package['message']
                self.login_session.close()
                return package
        else:
            # print('POST Unsuccessfully!')
            self.login_session.close()
            return {'result': False, 'message': '選課系統異常！無法登入！'}

    def login(self, _id, _pw):
        if self.server_status and self.secure_random:
            self.student_id = _id
            student_pw = _pw
            hash_pw = hashlib.md5(student_pw.encode("utf-8")).hexdigest()
            hash_pw = hmac.new(str.encode(hash_pw), digestmod=hashlib.sha256)
            hash_pw.update(str.encode(self.student_id))
            hash_pw.update(str.encode(self.secure_random))
            hash_pw = hash_pw.hexdigest()
            package = self.login_session.post(config.get_url('login'),
                                              data=config.get_payload(mode='login', userid=self.student_id,
                                                                       hash=hash_pw),
                                              headers=self.login_config.headers)
            # print(package.json())
            if package.status_code == 200:
                if package.json()['result']:
                    # 允許使用者名單
					sheet_id = 'xxxxxxxxxxxxxxxxxxxxxxx'
					sheet_gid = 'xxxxxxxxxxxxxxxxxxxxxxx'
                    allowed_user_list = requests.get('https://docs.google.com/spreadsheets/d/'+sheet_id+
                                                     '/export?format=csv&gid='+sheet_gid).text.split(
                                                     '\r\n')
                    # print(type(self.student_id))
                    tmp_hash = hashlib.sha256()
                    tmp_hash.update(self.student_id.encode('utf8'))
                    if tmp_hash.hexdigest().upper() in allowed_user_list:
                        self.allowed_id = True
                    self.login_status = True
                    self.login_config.set_headers(package.json()['pageId'])
                    return {'result': True, 'message': '登入成功！'}
                else:
                    return package.json()
            else:
                # print(config.msg_server_begin+'非學生作業時段！學生無法登入！')
                self.login_session.close()
                return {'result': False, 'message': '非學生作業時段！學生無法登入！'}

        else:
            # print(config.msg_server_begin+'非學生作業時段！學生無法登入！')
            self.login_session.close()

    def logout(self):
        self.login_status = False
        package = self.login_session.post(config.get_url('login'),
                                          data=config.get_payload(mode='logout'),
                                          headers=self.login_config.headers)
        if package.status_code == 200:
            # print('Logout Successfully!')
            # print(config.msg_logout)
            self.login_session.close()
        else:
            self.login_session.close()

    def get_session(self):
        return self.login_session

    def get_student_id(self):
        return self.student_id

    def check_status(self):
        if self.server_status:
            return True
        else:
            return False


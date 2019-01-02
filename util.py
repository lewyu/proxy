import json
import base64


def md5sum(plain):
    import hashlib
    hl = hashlib.md5()
    hl.update(str(plain).encode(encoding='utf-8'))
    crypt = hl.hexdigest()
    return crypt


def encode(dic):
    import json
    import base64

    ans = base64.b64encode(json.dumps(dic).encode(encoding='utf-8'))
    return ans


def decode(bytecode):
    import json
    import base64

    ans = json.loads(base64.b64decode(bytecode))
    return ans


if __name__ == '__main__':
    _data = {'op': 'ges', 'data': {'pkm': {'1': '2'}}}
    data = decode(encode(_data))
    print(data.get('data').get('pkm').get('1'))

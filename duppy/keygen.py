import os
import base64


def make_tsig_secret(bits=256):
    return str(base64.b64encode(os.urandom(bits // 8)).strip(), 'utf-8')


def make_tsig_keyfile(secret, name, algname='hmac-sha256'):
    return ('key "%s" {\n\talgorithm %s;\n\tsecret "%s";\n};\n'
        % (name, algname, secret))


if __name__ == '__main__':
    import sys

    args = sys.argv[1:] or ['example.com']
    if len(args) > 1:
        algo = args[1].lower()
        if 'md5' in algo:
            bits = 128
        elif 'sha1' in algo:
            bits = 160
        elif 'sha384' in algo:
            bits = 384
        elif 'sha512' in algo:
            bits = 512
        else:
            bits = 256
    else:
        bits = 256

    print('# Usage: %s [%s [hmac-sha256]]'
        % (os.path.basename(sys.argv[0]), args[0]))
    print(make_tsig_keyfile(make_tsig_secret(bits), *args))

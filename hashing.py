import hashlib
import hmac
import random
import string


def hash_str(s):
    return hmac.new("secret", s, hashlib.sha256).hexdigest()


def make_secure_val(s):
    return "{}|{}".format(s, hash_str(s))


def check_secure_val(h):
    val = h.split('|', 1)[0]
    if make_secure_val(val) == h:
        return val


def make_salt():
    return ''.join(random.choice(string.ascii_letters) for _ in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    name_pw_hash = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (name_pw_hash, salt)


def valid_pw(name, pw, h):
    db_hash, salt = h.split(',')
    computed_hash = make_pw_hash(name, pw, salt)
    return db_hash == computed_hash




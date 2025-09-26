import pickle
import subprocess

user_code = input("Enter code: ")
eval(user_code)  # unsafe eval

code = "print('hello')"
exec(code)  # unsafe exec

password = "123456"  # hardcoded password
print(f"Password is {password}")

data = pickle.loads(b"cos\nsystem\n(S'ls'\ntR.")  # unsafe deserialization

import requests
requests.get("https://example.com", verify=False)  # disables SSL verification

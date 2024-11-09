
# 🔐Pyssenger

Features:

A new Python Messenger that has Public and Private keys encryption. 

The main feature is that you can setup a password on your keys folder, so then they could be encrypted in zip folder.

Zip folder encryption would encode your code in Base64 and turn it into hash, so it would be impossible to bruteforce access.

Login/Signup page encrypted

Admin panel, which could be accessed by visiting /admin-panel page, url should've look like that ``127.0.0.1:5000/admin-panel``

Private/Public Channels creation

Invitation link generator





How to install:
- Clone a repository
```git clone https://github.com/SuurStofi/pyssenger/tree/main```

- Open main directory
``` cd Pyssenger ```

- Install requirements

``` pip install -r requirement.txt ```

- Launch main file

``` python3 launch.py ```

How to host it:

- You can use ngrok

```ngrok http 5000```

- Or you can use LocalTunel as an alternative

```ssh -R 80:localhost:5000 nokey@localhost.run```






About:

This is my first built web-project, i made it on solo with ai help, so you're free to leave review on that

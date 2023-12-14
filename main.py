# import cryptography

# from cryptography.fernet import Fernet
# # Put this somewhere safe!
# key = Fernet.generate_key()
# print(key.decode())
# f = Fernet(key)
# token = f.encrypt(b"A really secret message. Not for prying eyes.")
# print(token.decode())
# message = f.decrypt(token)
# print(message.decode())

# def generate_key():
#     return Fernet.generate_key()

# def encrypt_password(key, password):
#     f = Fernet(key)
#     return f.encrypt(password.encode()).decode()

# def decrypt_password(key, encrypted_password):
#     f = Fernet(key)
#     return f.decrypt(encrypted_password.encode()).decode()

# passwords = {}

# def add_password():
#     service = service_entry.get()
#     username = username_entry.get()
#     password = password_entry.get()

#     if service and username and password:
#         encrypted_password = encrypt_password(key, password)
#         passwords[service] = {'username': username, 'password': encrypted_password}
#         messagebox.showinfo("Success", "Password added successfully!")
#     else:
#         messagebox.showwarning("Error", "Please fill in all the fields.")
#     print(passwords)

# def get_password():
#     service = service_entry.get()
#     if service in passwords:
#         encrypted_password = passwords[service]['password']
#         decrypted_password = decrypt_password(key, encrypted_password)
#         messagebox.showinfo("Password", f"Username: {passwords[service]['username']}\nPassword: {decrypted_password}")
#     else:
#         messagebox.showwarning("Error", "Password not found.")

# key = generate_key()

# instructions = '''To add password fill all the fields and press "Add Password"
# To view password, enter Account Name and press "Get Password"'''
# signature = "Developed by Sai Satwik Bikumandla"

# window = tk.Tk()
# window.title("Password Manager")
# window.configure(bg="orange")

# window.resizable(False, False)


# center_frame = tk.Frame(window, bg="#d3d3d3")
# center_frame.grid(row=0, column=0, padx=10, pady=10)

# instruction_label = tk.Label(center_frame, text=instructions, bg="#d3d3d3")
# instruction_label.grid(row=0, column=1, padx=10, pady=5)

# service_label = tk.Label(center_frame, text="Account:", bg="#d3d3d3")
# service_label.grid(row=1, column=0, padx=10, pady=5)
# service_entry = tk.Entry(center_frame)
# service_entry.grid(row=1, column=1, padx=10, pady=5)

# username_label = tk.Label(center_frame, text="Username:", bg="#d3d3d3")
# username_label.grid(row=2, column=0, padx=10, pady=5)
# username_entry = tk.Entry(center_frame)
# username_entry.grid(row=2, column=1, padx=10, pady=5)

# password_label = tk.Label(center_frame, text="Password:", bg="#d3d3d3")
# password_label.grid(row=3, column=0, padx=10, pady=5)
# password_entry = tk.Entry(center_frame, show="*")
# password_entry.grid(row=3, column=1, padx=10, pady=5)


# add_button = tk.Button(center_frame, text="Add Password", height=1, width=10)
# add_button.grid(row=5, column=4, padx=10, pady=5)

# get_button = tk.Button(center_frame, text="Get Password", height=1, width=10)
# get_button.grid(row=6, column=4, padx=10, pady=5)

# signature_label = tk.Label(center_frame, text=signature, bg="#d3d3d3")
# signature_label.grid(row=7, column=1, padx=5, pady=5)


# window.mainloop()







# Author: Thomas Preston

import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import codecs
from uuid import uuid4
import json
import darkdetect

class PasswordManager():
    def __init__(self):
        self.readConfig()
        
    def readConfig(self):
        configFile = open("config.json", "r")
        configFileContents = configFile.read()

        noConfig = False
        if configFileContents.strip() == "":
            defaultConfigFile = open("defaultConfig.json", "r")
            configFileContents = defaultConfigFile.read()
            noConfig = True
        self.configData = json.loads(configFileContents)
        configFile.close()

        if noConfig == True:
            self.configFile = open("config.json", "w")
            self.configFile.write(json.dumps(self.configData, indent = 4))
            self.configFile.close()

        if self.configData["currentTheme"] == "defaultTheme":
            self.currentTheme = darkdetect.theme()
            self.configData["currentTheme"] = self.currentTheme
        else:
            self.currentTheme = self.configData["currentTheme"]

        self.windowWidth = self.configData["windowWidth"]
        self.windowHeight = self.configData["windowHeight"]
        self.backgroundColour = self.configData[f"{self.currentTheme}BackgroundColour"]
        self.foregroundColour = self.configData[f"{self.currentTheme}ForegroundColour"]
        self.highlightColour = self.configData[f"{self.currentTheme}HighlightColour"]
        self.textColour = self.configData[f"{self.currentTheme}TextColour"]

    def setTheme(self):
        if self.currentTheme == 'Dark':
            self.currentTheme = 'Light'
        else: 
            self.currentTheme = 'Dark'

        self.exitHandler()

    def windowConfig(self):
        self.window = tk.Tk()
        self.window.geometry(f"{self.windowWidth}x{self.windowHeight}")
        self.window.title("Password Manager")
        self.window.config(background = self.backgroundColour)

    def draw(self):
        self.window.rowconfigure(0, weight = 1)
        self.window.columnconfigure(0, weight = 1)

        self.mainFrame = tk.Frame(self.window, 
                                  background = self.backgroundColour)
        self.mainFrame.grid(row = 0, column = 0, sticky = "nsew")

        self.mainFrame.rowconfigure(0, weight = 1)
        self.mainFrame.columnconfigure(0, weight = 4)
        self.mainFrame.columnconfigure(1, weight = 1)

        passwordListFrame = tk.Frame(self.mainFrame, 
                                     background = self.backgroundColour,
                                     highlightthickness = "1", 
                                     highlightbackground = self.highlightColour)
        passwordListFrame.grid(row = 0, column = 0, sticky = "nsew")

        passwordListFrame.columnconfigure(0, weight = 1)
        passwordListFrame.columnconfigure(1, weight = 1)
        passwordListFrame.columnconfigure(2, weight = 1)
        passwordListFrame.rowconfigure(0, weight = 1)
        passwordListFrame.rowconfigure(1, weight = 10)

        title = tk.Label(passwordListFrame,
                         background = self.backgroundColour,
                         foreground = self.textColour,
                         text = "Passwords",
                         font = "Consolas 20")
        title.grid(row = 0, column = 0, columnspan = 3, sticky = "new", ipady = 10)

        infoListFrame = tk.Frame(passwordListFrame,
                                 background = self.backgroundColour)
        infoListFrame.grid(row = 1, column = 0, columnspan = 3, sticky = "new")

        infoListFrame.columnconfigure(0, weight = 1)
        infoListFrame.columnconfigure(1, weight = 1)
        infoListFrame.columnconfigure(2, weight = 1)
        infoListFrame.rowconfigure(0, weight = 1)

        self.accountsLabel = tk.Label(infoListFrame,
                                       background = self.backgroundColour,
                                       foreground = self.textColour,
                                       text = "Account:\n",
                                       font = "Consolas 12")
        self.accountsLabel.grid(row = 0, column = 0, sticky = "new", ipady = 10)

        self.usernamesLabel = tk.Label(infoListFrame,
                                       background = self.backgroundColour,
                                       foreground = self.textColour,
                                       text = "Username:\n",
                                       font = "Consolas 12")
        self.usernamesLabel.grid(row = 0, column = 1, sticky = "new", ipady = 10)

        self.passwordsLabel = tk.Label(infoListFrame,
                                       background = self.backgroundColour,
                                       foreground = self.textColour,
                                       text = "Password:\n",
                                       font = "Consolas 12")
        self.passwordsLabel.grid(row = 0, column = 2, sticky = "new", ipady = 10)

        optionsListFrame = tk.Frame(self.mainFrame, 
                                    background = self.foregroundColour, 
                                    highlightthickness = "1", 
                                    highlightbackground = self.highlightColour)
        optionsListFrame.grid(row = 0, column = 1, sticky = "nsew")

        optionsListFrame.columnconfigure(0, weight = 1)
        optionsListFrame.rowconfigure(0, weight = 2)
        optionsListFrame.rowconfigure(1, weight = 1)
        optionsListFrame.rowconfigure(2, weight = 1)
        optionsListFrame.rowconfigure(3, weight = 1)
        optionsListFrame.rowconfigure(4, weight = 1)
        optionsListFrame.rowconfigure(5, weight = 1)
        optionsListFrame.rowconfigure(6, weight = 1)
        optionsListFrame.rowconfigure(7, weight = 1)
        optionsListFrame.rowconfigure(8, weight = 1)
        optionsListFrame.rowconfigure(9, weight = 1)
        optionsListFrame.rowconfigure(10, weight = 1)
        optionsListFrame.rowconfigure(11, weight = 2)

        self.accountEntryLabel = tk.Label(optionsListFrame, 
                                background = self.foregroundColour,
                                foreground = self.textColour,
                                text = "Account:",
                                font = "Consolas 15")
        self.accountEntry = tk.Entry(optionsListFrame,
                                 background = self.foregroundColour,
                                 foreground = self.textColour,
                                 font = "Consolas 15",
                                 width = 12)

        self.usernameEntryLabel = tk.Label(optionsListFrame, 
                                 background = self.foregroundColour,
                                 foreground = self.textColour,
                                 text = "Username:",
                                 font = "Consolas 15") 
        self.usernameEntryLabel.grid(row = 3, column = 0, sticky = "nsew", padx = 10)
        self.usernameEntry = tk.Entry(optionsListFrame,
                                 background = self.foregroundColour,
                                 foreground = self.textColour,
                                 font = "Consolas 15",
                                 width = 12)
        self.usernameEntry.grid(row = 4, column = 0, sticky = "nsew", padx = 10)

        self.passwordEntryLabel = tk.Label(optionsListFrame,
                                 background = self.foregroundColour,
                                 foreground = self.textColour,
                                 text = "Password:",
                                 font = "Consolas 15")
        self.passwordEntryLabel.grid(row = 5, column = 0, sticky = "nsew", padx = 10)
        self.passwordEntry = tk.Entry(optionsListFrame,
                                 background = self.foregroundColour,
                                 foreground = self.textColour,
                                 font = "Consolas 15",
                                 show="*",
                                 width = 12)
        self.passwordEntry.grid(row = 6, column = 0, sticky = "nsew", padx = 10)

        self.loginButton = tk.Button(optionsListFrame, 
                               background = self.foregroundColour, 
                               foreground = self.textColour,
                               activebackground = self.backgroundColour,
                               activeforeground = self.textColour,
                               relief = "raised",
                               text="Login", 
                               font = "Consolas 15",
                               command = self.login)
        self.loginButton.grid(row = 8, column = 0, sticky = "ew", padx = 10)

        self.createButton = tk.Button(optionsListFrame, 
                               background = self.foregroundColour, 
                               foreground = self.textColour,
                               activebackground = self.backgroundColour,
                               activeforeground = self.textColour,
                               relief = "raised",
                               text="Sign Up", 
                               font = "Consolas 15",
                               command = self.signUp)
        self.createButton.grid(row = 9, column = 0, sticky = "ew", padx = 10)

        self.addButton = tk.Button(optionsListFrame, 
                               background = self.foregroundColour, 
                               foreground = self.textColour,
                               activebackground = self.backgroundColour,
                               activeforeground = self.textColour,
                               relief = "raised",
                               text="Add Password", 
                               font = "Consolas 15",
                               command = lambda: (self.addPassword(), self.drawPasswords()))
        
        smallButtonsFrame = tk.Frame(optionsListFrame, 
                                     background = self.foregroundColour)
        smallButtonsFrame.grid(row = 10, column = 0, sticky = "ew", padx = 10)
        smallButtonsFrame.columnconfigure(0, weight = 1)
        smallButtonsFrame.columnconfigure(1, weight = 1)
        smallButtonsFrame.rowconfigure(0, weight = 1)

        self.pageNumber = 1
        self.maxPage = 1

        previousPageButton = tk.Button(smallButtonsFrame, 
                                       background = self.foregroundColour, 
                                       foreground = self.textColour,
                                       activebackground = self.backgroundColour,
                                       activeforeground = self.textColour,
                                       relief = "raised",
                                       text="←",
                                       font = "Consolas 15",
                                       command = lambda: (setattr(self, "pageNumber", self.pageNumber-1) if self.pageNumber > 1 else None, self.drawPasswords()))
        previousPageButton.grid(row = 0, column = 0, sticky = "nsew", padx = 10)
        
        nextPageButton = tk.Button(smallButtonsFrame, 
                                   background = self.foregroundColour, 
                                   foreground = self.textColour,
                                   activebackground = self.backgroundColour,
                                   activeforeground = self.textColour,
                                   relief = "raised",
                                   text="→",
                                   font = "Consolas 15",
                                   command = lambda: (setattr(self, "pageNumber", self.pageNumber+1) if self.pageNumber <= self.maxPage else None, self.drawPasswords()))
        nextPageButton.grid(row = 0, column = 1, sticky = "nsew", padx = 10)

    def login(self):
        self.usernameEntryLabel.configure(foreground = self.textColour)
        self.passwordEntryLabel.configure(foreground = self.textColour)

        username = self.usernameEntry.get()
        password = self.passwordEntry.get()

        if username.strip() == "":
            self.usernameEntryLabel.configure(foreground = "#bb0000")
            return
        if password.strip() == "":
            self.passwordEntryLabel.configure(foreground = "#bb0000")
            return

        loginFile = open("logins.json", "r")
        loginData = json.loads(loginFile.read())
        loginFile.close()

        usernameDigest = hashes.Hash(hashes.SHA256())
        passwordDigest = hashes.Hash(hashes.SHA256())

        usernameDigest.update(username.encode("utf-8"))
        self.hashedUsername = codecs.encode(usernameDigest.finalize(), 'hex').decode("utf-8")
        salt = list(loginData[self.hashedUsername])[0]
        
        passwordDigest.update(salt.encode())
        passwordDigest.update(password.encode("utf-8"))
        self.hashedPassword = codecs.encode(passwordDigest.finalize(), 'hex').decode("utf-8")
        # f77dbdf4e6989156250f5f314671e4360eb7136c7cb01a8d28737f7c732df95b

        if self.hashedUsername in loginData:
            self.usernameEntryLabel.configure(foreground = self.textColour)
            if list(loginData[self.hashedUsername].values())[0] == self.hashedPassword:
                keyDigest = hashes.Hash(hashes.SHA256())
                keyDigest.update(salt.encode())
                keyDigest.update(username.encode("utf-8"))
                keyDigest.update(password.encode("utf-8"))
                self.key = codecs.encode(keyDigest.finalize(), 'base64')

                self.accountEntryLabel.grid(row = 1, column = 0, sticky = "nsew", padx = 10)
                self.accountEntry.grid(row = 2, column = 0, sticky = "nsew", padx = 10)
                self.addButton.grid(row = 8, column = 0, sticky = "ew", padx = 10)

                self.loginButton.grid_forget()
                self.createButton.grid_forget()

                self.passwordEntryLabel.configure(foreground = self.textColour)

                self.usernameEntry.delete(0, tk.END)
                self.passwordEntry.delete(0, tk.END)

                self.drawPasswords()
            else:
                self.passwordEntryLabel.configure(foreground = "#bb0000")
        else:
            self.usernameEntryLabel.configure(foreground = "#bb0000")

    def signUp(self):
        self.usernameEntryLabel.configure(foreground = self.textColour)
        self.passwordEntryLabel.configure(foreground = self.textColour)

        username = self.usernameEntry.get()
        password = self.passwordEntry.get()

        if username.strip() == "":
            self.usernameEntryLabel.configure(foreground = "#bb0000")
            return
        if password.strip() == "":
            self.passwordEntryLabel.configure(foreground = "#bb0000")
            return

        loginFile = open("logins.json", "r")
        loginFileContents = loginFile.read()
        if loginFileContents.strip() == "":
            loginFileContents = "{}"
        loginData = json.loads(loginFileContents)
        loginFile.close()

        usernameDigest = hashes.Hash(hashes.SHA256())
        passwordDigest = hashes.Hash(hashes.SHA256())

        salt = uuid4().hex

        passwordDigest.update(salt.encode())

        usernameDigest.update(username.encode("utf-8"))
        passwordDigest.update(password.encode("utf-8"))

        self.hashedUsername = codecs.encode(usernameDigest.finalize(), 'hex').decode("utf-8")
        self.hashedPassword = codecs.encode(passwordDigest.finalize(), 'hex').decode("utf-8")

        keyDigest = hashes.Hash(hashes.SHA256())
        keyDigest.update(salt.encode())
        keyDigest.update(username.encode("utf-8"))
        keyDigest.update(password.encode("utf-8"))
        self.key = codecs.encode(keyDigest.finalize(), 'base64')

        if self.hashedUsername not in loginData:
            loginData.update({self.hashedUsername: {salt: self.hashedPassword}})

            loginFile = open("logins.json", "w")
            loginFile.write(json.dumps(loginData))
            loginFile.close()

            self.accountEntryLabel.grid(row = 1, column = 0, sticky = "nsew", padx = 10)
            self.accountEntry.grid(row = 2, column = 0, sticky = "nsew", padx = 10)
            self.addButton.grid(row = 8, column = 0, sticky = "ew", padx = 10)

            self.loginButton.grid_forget()
            self.createButton.grid_forget()

            self.passwordEntryLabel.configure(foreground = self.textColour)

            self.usernameEntry.delete(0, tk.END)
            self.passwordEntry.delete(0, tk.END)

            passwordFile = open(f"Passwords\\{self.hashedUsername}.json", "w")
            passwordFile.write(json.dumps({}))
            passwordFile.close()

            self.drawPasswords()
            
        else:
            self.usernameEntryLabel.configure(foreground = "#bb0000")

    def getPasswords(self):
        passwordFile = open(f"Passwords\\{self.hashedUsername}.json", "r")
        encryptedPasswordData = json.loads(passwordFile.read())
        passwordFile.close()

        passwordData = {}

        f = Fernet(self.key)
        for account in encryptedPasswordData.keys():
            decryptedAccount = f.decrypt(account.encode()).decode()
            if decryptedAccount not in passwordData:
                passwordData.update({decryptedAccount: {}})
            for username in encryptedPasswordData[account].keys():
                decryptedUsername = f.decrypt(username.encode()).decode()
                decryptedPassword = f.decrypt(encryptedPasswordData[account][username].encode()).decode()
                passwordData[decryptedAccount].update({decryptedUsername: decryptedPassword})
        return passwordData

    def drawPasswords(self):
        try:
            self.hashedUsername
            self.hashedPassword
        except AttributeError:
            return
        
        if self.pageNumber > self.maxPage:
            self.pageNumber -= 1
            return
        
        passwordData = self.getPasswords()

        accounts = ""
        usernames = ""
        passwords = ""

        counter = 0
        accountCounter = 0
        keyCounterSum = 0

        morePages = False
        
        for account in passwordData.keys():
            accountCounter += 1
            if keyCounterSum < (self.pageNumber-1)*15:
                keyCounterSum += len(passwordData[account].keys())
                continue
            accounts += f"{account}\n"
            accounts += f"{"\n"*(len(passwordData[account].keys())-1)}"
            for username in passwordData[account].keys():
                counter += 1
                usernames += f"{username}\n"
                passwords += f"{passwordData[account][username]}\n"
            if counter >= (15*self.pageNumber):
                morePages = True
                break
        
        if morePages == True:
            if self.maxPage < self.pageNumber + 1:
                self.maxPage = self.pageNumber + 1

        accountsInfo = f"Account:\n{accounts.title()}"
        self.accountsLabel.config(text = accountsInfo)
        
        usernamesInfo = f"Username:\n{usernames}"
        self.usernamesLabel.config(text = usernamesInfo)

        passwordsInfo = f"Password:\n{passwords}"
        self.passwordsLabel.config(text = passwordsInfo)

    def addPassword(self):
        account = self.accountEntry.get().lower()
        username = self.usernameEntry.get()
        password = self.passwordEntry.get()

        passwordData = self.getPasswords()

        # f = Fernet(key)
        # return f.encrypt(password.encode()).decode()

        f = Fernet(self.key)

        # encryptedAccount = f.encrypt(account.encode()).decode()
        # encryptedUsername = f.encrypt(username.encode()).decode()
        # encryptedPassword = f.encrypt(password.encode()).decode()

        if account not in passwordData:
            passwordData.update({account: {username: password}})
        else:
            if username not in passwordData[account]:
                passwordData[account].update({username: password})
            elif passwordData[account][username] != password:
                response = messagebox.askyesno(title = "Warning", message = "Would you like to override these details", icon = "warning", parent = self.window)

                if response:
                    passwordData[account].update({username: password})
                else:
                    return
            else:
                messagebox.showinfo(title = "Duplicate Data", message = "This username and password already exists for this account", icon = "warning", parent = self.window)

        encryptedPasswordData = {}

        for account in passwordData.keys():
            encryptedAccount = f.encrypt(account.encode()).decode()
            if encryptedAccount not in encryptedPasswordData:
                encryptedPasswordData.update({encryptedAccount: {}})
            for username in passwordData[account].keys():
                encryptedUsername = f.encrypt(username.encode()).decode()
                encryptedPassword = f.encrypt(passwordData[account][username].encode()).decode()
                encryptedPasswordData[encryptedAccount].update({encryptedUsername: encryptedPassword})

        passwordFile = open(f"Passwords\\{self.hashedUsername}.json", "w")
        passwordFile.write(json.dumps(encryptedPasswordData))
        passwordFile.close()

    def run(self):
        self.windowConfig()
        self.draw()
        self.window.mainloop()

manager = PasswordManager()
manager.run()
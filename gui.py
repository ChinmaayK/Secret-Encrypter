from customtkinter import *
from cryptography.fernet import Fernet
from tkinter import messagebox


class Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Generate Secret File")
        self.root.geometry("1200x600")
        set_appearance_mode("dark")
        set_default_color_theme("dark-blue")
        self.gui()

    def gui(self):
        self.root.columnconfigure((0, 1, 2), weight=1, uniform="a")
        self.root.rowconfigure(2, weight=1)
        self.root.rowconfigure(3, weight=1)

        lbl = CTkLabel(self.root, text="Secret File Generator", text_color="#C3C3C3", anchor=W, font=("Berlin Sans FB Demi", 48, "bold"))
        lbl.grid(row=0, column=0, sticky=W, padx=60, pady=25, columnspan=2)

        tab_manager = CTkTabview(self.root, fg_color="transparent")
        tab_manager.grid(row=1, column=0, padx=(60, 0), sticky=NW, columnspan=4)

        # Create Tabs
        encrypt_tab = tab_manager.add("Encrypt")
        decrypt_tab = tab_manager.add("Decrypt")

        encrypt_frame = CTkFrame(encrypt_tab, fg_color="transparent")
        encrypt_frame.grid()
        self.encrypt_widgets(encrypt_frame)

        decrypt_frame = CTkFrame(decrypt_tab, fg_color="transparent")
        decrypt_frame.grid()
        self.decrypt_widgets(decrypt_frame)

    def encrypt_widgets(self, frame):
        self.encrypt_img_file = CTkEntry(frame, placeholder_text="JPG file Path", width=520)
        self.encrypt_img_file.grid(row=0, column=0, padx=0, sticky=NW, columnspan=2, ipadx=30, pady=0)

        open_img_file = CTkButton(frame, text="Open", fg_color="transparent", hover_color="#2D2D2D", border_width=2, text_color=("gray10", "#DCE4EE"), command=lambda: self.open_jpg_file(self.encrypt_img_file))
        open_img_file.grid(row=0, column=0, sticky=NW, pady=0, padx=(590, 0), columnspan=3)

        self.encrypt_password = CTkEntry(frame, placeholder_text="Password", width=250)
        self.encrypt_password.grid(row=1, column=0, padx=(0, 0), sticky=NW, columnspan=2, ipadx=30, pady=20)

        self.encrypt_salt = CTkEntry(frame, placeholder_text="Salt", width=250)
        self.encrypt_salt.grid(row=1, column=0, padx=340, sticky=NW, columnspan=2, ipadx=30, pady=20)

        self.encrypt_folder_inp = CTkEntry(frame, placeholder_text="Folder Path to Encrypt", width=520)
        self.encrypt_folder_inp.grid(row=1, column=0, padx=0, sticky=NW, columnspan=2, ipadx=30, pady=75)

        open_folder = CTkButton(frame, text="Open", fg_color="transparent", hover_color="#2D2D2D", border_width=2, text_color=("gray10", "#DCE4EE"), command=lambda: self.open_folder_enc(self.encrypt_folder_inp))
        open_folder.grid(row=1, column=0, sticky=NW, pady=75, padx=(590, 0), columnspan=3)

        self.encrypt_output = CTkEntry(frame, placeholder_text="Output Path", width=520)
        self.encrypt_output.grid(row=1, column=0, padx=0, sticky=NW, columnspan=2, ipadx=30, pady=130)

        open_out_path = CTkButton(frame, text="Open", fg_color="transparent", hover_color="#2D2D2D", border_width=2, text_color=("gray10", "#DCE4EE"), command=lambda: self.save_as_file_enc(self.encrypt_output))
        open_out_path.grid(row=1, column=0, sticky=NW, pady=130, padx=(590, 0), columnspan=3)

        encrypt_btn = CTkButton(frame, text="Encrypt", font=("Berlin Sans FB Demi", 20, "bold"), width=300, height=40, command=self.encrypt)
        encrypt_btn.grid(row=2, column=0, sticky=W, columnspan=2, ipadx=20, padx=(0, 0))

    def decrypt_widgets(self, frame):
        self.decrypt_img_file = CTkEntry(frame, placeholder_text="JPG file Path", width=520)
        self.decrypt_img_file.grid(row=0, column=0, padx=0, sticky=NW, columnspan=2, ipadx=30, pady=0)

        open_img_file = CTkButton(frame, text="Open", fg_color="transparent", hover_color="#2D2D2D", border_width=2, text_color=("gray10", "#DCE4EE"), command=lambda: self.open_jpg_file(self.decrypt_img_file))
        open_img_file.grid(row=0, column=0, sticky=NW, pady=0, padx=(590, 0), columnspan=3)

        self.decrypt_password = CTkEntry(frame, placeholder_text="Password", width=250)
        self.decrypt_password.grid(row=1, column=0, padx=(0, 0), sticky=NW, columnspan=2, ipadx=30, pady=20)

        self.decrypt_salt = CTkEntry(frame, placeholder_text="Salt", width=250)
        self.decrypt_salt.grid(row=1, column=0, padx=340, sticky=NW, columnspan=2, ipadx=30, pady=20)

        self.decrypt_output = CTkEntry(frame, placeholder_text="Output Folder Path", width=520)
        self.decrypt_output.grid(row=1, column=0, padx=0, sticky=NW, columnspan=2, ipadx=30, pady=75)

        open_out_path = CTkButton(frame, text="Open", fg_color="transparent", hover_color="#2D2D2D", border_width=2, text_color=("gray10", "#DCE4EE"), command=lambda: self.save_as_file_dec(self.decrypt_output))
        open_out_path.grid(row=1, column=0, sticky=NW, pady=75, padx=(590, 0), columnspan=3)

        decrypt_btn = CTkButton(frame, text="Decrypt", font=("Berlin Sans FB Demi", 20, "bold"), width=300, height=40, command=self.decrypt)
        decrypt_btn.grid(row=2, column=0, sticky=W, columnspan=2, ipadx=20, padx=(0, 0))

    def open_jpg_file(self, entry):
        path = filedialog.askopenfilename(defaultextension=".jpg",filetypes=[("jpg", "*.jpg")])
        if path:
            entry.delete(0, END)
            entry.insert(0, path)

    def open_folder_enc(self, entry):
        path = filedialog.askdirectory()
        if path:
            entry.delete(0, END)
            entry.insert(0, path)

    def save_as_file_enc(self, entry):
        path = filedialog.asksaveasfilename(defaultextension=".jpg",filetypes=[("jpg", "*.jpg")])
        if path:
            entry.delete(0, END)
            entry.insert(0, path)

    def save_as_file_dec(self, entry):
        path = filedialog.askdirectory()
        if path:
            entry.delete(0, END)
            entry.insert(0, path)

    def encrypt(self):
        from Encrypt import main, gen_key
        password = self.encrypt_password.get()
        salt = self.encrypt_salt.get()
        key = gen_key(password, salt)
        # key = encrypt_gen_key("password", "salt")
        main(self.encrypt_img_file.get(), self.encrypt_folder_inp.get(), self.encrypt_output.get(), None, key)

    def decrypt(self):
        from Decrypt import main, gen_key
        password = self.decrypt_password.get()
        salt = self.decrypt_salt.get()
        key = gen_key(password, salt)
        f = Fernet(key)
        main(self.decrypt_img_file.get(), f"{self.decrypt_output.get()}/decrypted_folder", f)


root = CTk()
Dashboard(root)
root.mainloop()

import customtkinter as ctk
from tkinter import messagebox
import config as cf
import database as db
import utils as ut

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def clear_window(win):
    for widget in win.winfo_children():
        widget.destroy()


def set_pin_window(win):
    clear_window(win)

    if not cf.is_first_run():
        pin_window(win)
        return

    def save_first_pin():
        if not pin_entry.get() or not confirm_pin_entry.get():
            messagebox.showerror("Error", "All fields are required.")
            return
        if pin_entry.get() != confirm_pin_entry.get():
            messagebox.showerror("Error", "The new PIN and confirmation dont match.")
            return
        cf.set_pin(pin_entry.get())
        messagebox.showinfo("Info", "Pin set successfully")
        pin_window(win)
        cf.toggle_first_run()

    ctk.CTkLabel(win, text="Set your security PIN", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(20, 10))
    ctk.CTkLabel(win, text="Security PIN").pack()
    pin_entry = ctk.CTkEntry(win, show="*", width=200)
    pin_entry.pack(pady=5)
    ctk.CTkLabel(win, text="Confirm security PIN").pack()
    confirm_pin_entry = ctk.CTkEntry(win, show="*", width=200)
    confirm_pin_entry.pack(pady=5)
    ctk.CTkButton(win, text="Save", command=save_first_pin, width=200).pack(pady=10)


def change_pin_window(win):
    def change_pin():
        if not old_pin_entry.get() or not new_pin_entry.get() or not confirm_pin_entry.get():
            messagebox.showerror("Error", "All fields are required.")
            return
        if not cf.verify_pin(old_pin_entry.get()):
            messagebox.showerror("Error", "Incorrect security PIN.")
            return
        if new_pin_entry.get() != confirm_pin_entry.get():
            messagebox.showerror("Error", "The new PIN and confirmation dont match.")
            return
        cf.set_pin(new_pin_entry.get())
        messagebox.showinfo("Info", "PIN changed successfully")
        pin_window(win)

    clear_window(win)
    ctk.CTkLabel(win, text="Change PIN", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(20, 10))
    ctk.CTkLabel(win, text="Old PIN").pack()
    old_pin_entry = ctk.CTkEntry(win, show="*", width=200)
    old_pin_entry.pack(pady=5)
    ctk.CTkLabel(win, text="New PIN").pack()
    new_pin_entry = ctk.CTkEntry(win, show="*", width=200)
    new_pin_entry.pack(pady=5)
    ctk.CTkLabel(win, text="Confirm new PIN").pack()
    confirm_pin_entry = ctk.CTkEntry(win, show="*", width=200)
    confirm_pin_entry.pack(pady=5)
    ctk.CTkButton(win, text="Save", command=change_pin, width=200).pack(pady=5)
    ctk.CTkButton(win, text="Back", command=lambda: pin_window(win), width=200, fg_color="transparent", border_width=1).pack(pady=5)


def pin_window(win):
    def confirm_pin():
        if cf.verify_pin(pin_entry.get()):
            view_window(win)
        else:
            messagebox.showerror("Error", "Incorrect security PIN.")
            pin_entry.delete(0, ctk.END)

    clear_window(win)
    ctk.CTkLabel(win, text="Enter security PIN", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(20, 10))
    pin_entry = ctk.CTkEntry(win, show="*", width=200)
    pin_entry.pack(pady=5)
    ctk.CTkButton(win, text="Enter", command=confirm_pin, width=200).pack(pady=5)
    ctk.CTkButton(win, text="Change PIN", command=lambda: change_pin_window(win), width=200, fg_color="transparent", border_width=1).pack(pady=5)
    ctk.CTkButton(win, text="Back", command=lambda: main_window(win), width=200, fg_color="transparent", border_width=1).pack(pady=5)


def view_window(win):
    clear_window(win)
    win.geometry("500x650")
    passwords = db.get_passwords()
    selected_index = [None]

    def copy_password():
        if not password_entry.get():
            messagebox.showwarning("Warning", "Nothing to copy.")
            return
        win.clipboard_clear()
        win.clipboard_append(password_entry.get())
        win.update()
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def delete_selected():
        index = selected_index[0]
        if index is None:
            messagebox.showerror("Error", "You must select an item from the list.")
            return
        pass_id = passwords[index][0]
        website = passwords[index][1]
        confirm = messagebox.askyesno("Confirm Deletion", f'Are you sure you want to delete the password for "{website}"?')
        if confirm:
            db.delete_password(pass_id)
            view_window(win)

    def update_selected():
        index = selected_index[0]
        if index is None:
            messagebox.showerror("Error", "You must select an item from the list.")
            return
        pass_id = passwords[index][0]
        new_website = website_entry.get()
        new_user = user_entry.get()
        if not new_website or not new_user:
            messagebox.showerror("Error", "Website and Username are required.")
            return
        db.update_password(pass_id, new_website, new_user)
        messagebox.showinfo("Success", "Data updated successfully.")
        view_window(win)

    def on_select(event):
        selected = password_listbox.curselection()
        if selected:
            index = selected[0]
            selected_index[0] = index
            password = passwords[index]
            website_entry.delete(0, ctk.END)
            website_entry.insert(0, password[1])
            user_entry.delete(0, ctk.END)
            user_entry.insert(0, password[2])
            password_entry.configure(state="normal")
            password_entry.delete(0, ctk.END)
            password_entry.insert(0, password[3])
            password_entry.configure(state="readonly")

    ctk.CTkLabel(win, text="Saved Passwords", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 5))

    import tkinter as tk
    password_listbox = tk.Listbox(win, bg="#2b2b2b", fg="white", selectbackground="#1f538d", width=40, height=8, relief="flat")
    password_listbox.pack(padx=20, pady=5)
    for p in passwords:
        password_listbox.insert(tk.END, p[1])
    password_listbox.bind("<<ListboxSelect>>", on_select)

    ctk.CTkLabel(win, text="Website").pack()
    website_entry = ctk.CTkEntry(win, width=300)
    website_entry.pack(pady=2)

    ctk.CTkLabel(win, text="Username / Email").pack()
    user_entry = ctk.CTkEntry(win, width=300)
    user_entry.pack(pady=2)

    ctk.CTkLabel(win, text="Password").pack()
    pass_frame = ctk.CTkFrame(win, fg_color="transparent")
    pass_frame.pack(pady=2)
    password_entry = ctk.CTkEntry(pass_frame, state="readonly", width=240)
    password_entry.pack(side="left", padx=(0, 5))
    ctk.CTkButton(pass_frame, text="Copy", command=copy_password, width=60).pack(side="left")

    btn_frame = ctk.CTkFrame(win, fg_color="transparent")
    btn_frame.pack(pady=10)
    ctk.CTkButton(btn_frame, text="Update", command=update_selected, width=120).pack(side="left", padx=5)
    ctk.CTkButton(btn_frame, text="Delete", command=delete_selected, width=120, fg_color="red", hover_color="#aa0000").pack(side="left", padx=5)
    ctk.CTkButton(win, text="Back", command=lambda: main_window(win), width=200, fg_color="transparent", border_width=1).pack(pady=5)


def add_window(win):
    def add_password():
        website = website_entry.get()
        user = user_entry.get()
        password = password_entry.get()
        confirm = confirm_entry.get()
        if not website or not user or not password or not confirm:
            messagebox.showerror("Error", "All fields are required.")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords dont match.")
            return
        db.save_password(website, user, password)
        website_entry.delete(0, ctk.END)
        user_entry.delete(0, ctk.END)
        password_entry.delete(0, ctk.END)
        confirm_entry.delete(0, ctk.END)
        messagebox.showinfo("Success", "Password saved successfully.")

    def toggle(entry, btn):
        if entry.cget("show") == "":
            entry.configure(show="*")
            btn.configure(text="Show")
        else:
            entry.configure(show="")
            btn.configure(text="Hide")

    clear_window(win)
    ctk.CTkLabel(win, text="Add Password", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(20, 10))

    ctk.CTkLabel(win, text="Website").pack()
    website_entry = ctk.CTkEntry(win, width=300)
    website_entry.pack(pady=5)

    ctk.CTkLabel(win, text="User or Email").pack()
    user_entry = ctk.CTkEntry(win, width=300)
    user_entry.pack(pady=5)

    ctk.CTkLabel(win, text="Password").pack()
    pass_frame = ctk.CTkFrame(win, fg_color="transparent")
    pass_frame.pack(pady=2)
    password_entry = ctk.CTkEntry(pass_frame, show="*", width=240)
    password_entry.pack(side="left", padx=(0, 5))

    def generate():
        pwd = ut.generate_password()
        password_entry.configure(state="normal", show="")
        password_entry.delete(0, ctk.END)
        password_entry.insert(0, pwd)
        confirm_entry.delete(0, ctk.END)
        confirm_entry.insert(0, pwd)
        toggle_pass_btn.configure(text="Hide")

    generate_btn = ctk.CTkButton(pass_frame, text="Generate", width=80, command=generate)
    generate_btn.pack(side="left", padx=(0, 5))
    toggle_pass_btn = ctk.CTkButton(pass_frame, text="Show", width=60, command=lambda: toggle(password_entry, toggle_pass_btn))
    toggle_pass_btn.pack(side="left")

    ctk.CTkLabel(win, text="Confirm Password").pack()
    confirm_frame = ctk.CTkFrame(win, fg_color="transparent")
    confirm_frame.pack(pady=2)
    confirm_entry = ctk.CTkEntry(confirm_frame, show="*", width=240)
    confirm_entry.pack(side="left", padx=(0, 5))
    toggle_confirm_btn = ctk.CTkButton(confirm_frame, text="Show", width=60, command=lambda: toggle(confirm_entry, toggle_confirm_btn))
    toggle_confirm_btn.pack(side="left")

    ctk.CTkButton(win, text="Add", command=add_password, width=200).pack(pady=10)
    ctk.CTkButton(win, text="Back", command=lambda: main_window(win), width=200, fg_color="transparent", border_width=1).pack(pady=5)


def main_window(win=None):
    db.init_db()
    cf.toggle_first_run()

    if win is None:
        win = ctk.CTk()
        win.geometry("500x500")
        win.resizable(False, False)
        win.title("Password Manager")
    else:
        win.geometry("500x500")

    clear_window(win)
    ctk.CTkLabel(win, text="Password Manager", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(40, 20))
    ctk.CTkButton(win, text="Add Password", command=lambda: add_window(win), width=200, height=40).pack(pady=10)
    ctk.CTkButton(win, text="View Passwords", command=lambda: set_pin_window(win), width=200, height=40).pack(pady=10)
    ctk.CTkButton(win, text="Exit", command=win.destroy, width=200, height=40, fg_color="transparent", border_width=1).pack(pady=10)

    if not hasattr(win, '_initialized'):
        win._initialized = True
        win.mainloop()


if __name__ == '__main__':
    main_window()
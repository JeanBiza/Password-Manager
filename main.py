import functions as f
import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

def clear_window(win):
    for widget in win.winfo_children():
        widget.destroy()

def set_pin_window(win):
    clear_window(win)

    if not f.is_first_run():
        pin_window(win)
        return

    def save_first_pin():
        if not pin_entry.get() or not confirm_pin_entry.get():
            messagebox.showerror("Error", "All fields are required.")
            return
        if pin_entry.get() != confirm_pin_entry.get():
            messagebox.showerror("Error", "The new PIN and confirmation dont match.")
            return

        f.set_pin(pin_entry.get())
        messagebox.showinfo("Info", "Pin set successfully")
        pin_window(win)
        f.toggle_first_run()

    set_pin_label = tk.Label(win, text="Set your security PIN.")
    set_pin_label.pack()

    pin_label = tk.Label(win, text="security PIN")
    pin_label.pack()
    pin_entry = tk.Entry(win, show="*")
    pin_entry.pack()

    confirm_pin_label = tk.Label(win, text="Confirm security PIN")
    confirm_pin_label.pack()
    confirm_pin_entry = tk.Entry(win, show="*")
    confirm_pin_entry.pack()

    save_pin_btn = tk.Button(win, text="Save", command=save_first_pin)
    save_pin_btn.pack()


def change_pin_window(win):

    def change_pin():
        pin = f.get_pin()

        if not old_pin_entry.get() or not new_pin_entry.get() or not confirm_pin_entry.get():
            messagebox.showerror("Error", "All fields are required.")
            return
        if old_pin_entry.get() != pin:
            messagebox.showerror("Error", "Incorrect Security pin")
            return
        if new_pin_entry.get() != confirm_pin_entry.get():
            messagebox.showerror("Error", "The new PIN and confirmation dont match.")
            return

        f.set_pin(new_pin_entry.get())
        messagebox.showinfo("Info", "PIN changed successfully")
        pin_window(win)


    clear_window(win)

    old_pin_label = tk.Label(win, text="Old pin")
    old_pin_label.pack()
    old_pin_entry = tk.Entry(win, show="*")
    old_pin_entry.pack()

    new_pin_label = tk.Label(win, text="New pin")
    new_pin_label.pack()
    new_pin_entry = tk.Entry(win, show="*")
    new_pin_entry.pack()

    confirm_pin_label = tk.Label(win, text="Confirm pin")
    confirm_pin_label.pack()
    confirm_pin_entry = tk.Entry(win, show="*")
    confirm_pin_entry.pack()

    save_btn = tk.Button(win, text="Save", command=change_pin)
    save_btn.pack()

    back_btn = tk.Button(win, text="Back", command= lambda : pin_window(win))
    back_btn.pack()


def pin_window(win):
    pin = f.get_pin()
    def confirm_pin():
        if pin == pin_entry.get():
            view_window(win)
        else:
            messagebox.showerror("Error", "Incorrect security pin.")
            pin_entry.delete(0, tk.END)


    clear_window(win)
    pin_label = tk.Label(win, text="Enter security pin")
    pin_label.pack()

    pin_entry = tk.Entry(win, show='*')
    pin_entry.pack()

    pin_btn = tk.Button(win, text="Enter", command=confirm_pin)
    pin_btn.pack()

    change_btn = tk.Button(win, text="Change pin", command= lambda : change_pin_window(win))
    change_btn.pack()

    back_btn = tk.Button(win, text="Back", command=lambda : main_window(win))
    back_btn.pack()


def view_window(win):
    clear_window(win)
    passwords = f.get_passwords()
    selected_index = [None]

    def copy_password():
        if not password_entry.get():
            messagebox.showwarning("Warning", "nothing for copy")
            return
        win.clipboard_clear()
        win.clipboard_append(password_entry.get())
        win.update()
        messagebox.showinfo("Copied", "Password copied to clipboard")

    def update_list():
        for i in range(len(passwords)):
            password_list.insert(tk.END, passwords[i][1])

    def delete_selected():
        index = selected_index[0]
        if index is None:
            messagebox.showerror("Error", "You must select an item from the list")
            return

        pass_id = passwords[index][0]
        website = passwords[index][1]

        confirm = messagebox.askyesno("Confirm Deletion", f'Are you sure you want delete the password for "{website}"?')
        if confirm:
            f.delete_password(pass_id)
            view_window(win)

    def update_selected():
        index = selected_index[0]
        if index is None:
            messagebox.showerror("Error", "You must select an item from the list")
            return

        pass_id = passwords[index][0]
        new_website = website_entry.get()
        new_user = user_entry.get()

        if not new_website or not new_user:
            messagebox.showerror("Error", "Website and Username are required")
            return

        f.update_password(pass_id, new_website, new_user)
        messagebox.showinfo("Success", "Data updated successfully")
        view_window(win)

    def on_select(event):
        selected = password_list.curselection()
        if selected:
            index = selected[0]
            selected_index[0] = index
            password = passwords[index]

            website_entry.delete(0, tk.END)
            website_entry.insert(0, password[1])

            user_entry.delete(0, tk.END)
            user_entry.insert(0, password[2])

            password_entry.config(state = 'normal')
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password[3])
            password_entry.config(state='readonly')

    password_list = tk.Listbox(win)
    password_list.pack()
    update_list()
    password_list.bind("<<ListboxSelect>>", on_select)

    website_label = tk.Label(win, text="Website")
    website_label.pack()
    website_entry = tk.Entry(win)
    website_entry.pack()

    user_label = tk.Label(win, text="Username / Email")
    user_label.pack()
    user_entry = tk.Entry(win)
    user_entry.pack()


    password_label = tk.Label(win, text="Password")
    password_label.pack()

    password_frame = tk.Frame(win)
    password_frame.pack()
    password_entry = tk.Entry(password_frame, state='readonly')
    password_entry.pack(side="left")


    copy_btn = tk.Button(password_frame, text="Copy",command=copy_password)
    copy_btn.pack()


    update_btn = tk.Button(win, text="Update", command=update_selected)
    update_btn.pack()

    delete_btn = tk.Button(win, text="Delete", command=delete_selected)
    delete_btn.pack()

    back_btn = tk.Button(win, text="Back", command=lambda : main_window(win))
    back_btn.pack()

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
            tk.messagebox.showerror("Error", "Passwords dont match")
            return

        f.save_password(website, user, password)

        website_entry.delete(0, tk.END)
        user_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        confirm_entry.delete(0,tk.END)

    def toggle_password():
        if password_entry.cget('show') == '':
            password_entry.config(show='*')
            toggle_pass_btn.config(text="Show")
        else:
            password_entry.config(show='')
            toggle_pass_btn.config(text='Hide')

    def toggle_confirm():
        if confirm_entry.cget('show') == '':
            confirm_entry.config(show='*')
            toggle_confirm_btn.config(text="Show")
        else:
            confirm_entry.config(show='')
            toggle_confirm_btn.config(text='Hide')


    clear_window(win)

    main_label = tk.Label(win, text="Add password")
    main_label.pack()

    website_label = tk.Label(win, text="Website")
    website_label.pack()
    website_entry = tk.Entry(win)
    website_entry.pack()

    user_label = tk.Label(win, text="User or email")
    user_label.pack()
    user_entry = tk.Entry(win)
    user_entry.pack()

    password_label = tk.Label(win, text="Password")
    password_label.pack()


    password_frame = tk.Frame(win)
    password_frame.pack()
    password_entry = tk.Entry(password_frame, show='*')
    password_entry.pack(side= "left")
    toggle_pass_btn = tk.Button(password_frame, text="Show", command=toggle_password)
    toggle_pass_btn.pack(side="left", padx=5)

    confirm_label = tk.Label(win, text="Confirm Password")
    confirm_label.pack()

    confirm_frame = tk.Frame(win)
    confirm_frame.pack()
    confirm_entry = tk.Entry(confirm_frame, show='*')
    confirm_entry.pack(side="left")
    toggle_confirm_btn = tk.Button(confirm_frame, text="Show", command=toggle_confirm)
    toggle_confirm_btn.pack(side="left", padx=5)

    add_pass_btn = tk.Button(win, text="Add", command=lambda : add_password())
    add_pass_btn.pack()


    back_btn = tk.Button(win, text="Back", command=lambda : main_window(win))
    back_btn.pack()

def main_window(win=None):
    f.init_db()
    f.toggle_first_run()

    if win is None:
        win = ttk.Window(themename="darkly")
        win.geometry("500x400")
        win.resizable(False, False)

    clear_window(win)
    win.title("Password manager")
    add_btn = tk.Button(text="Add Password", command=lambda : add_window(win))
    add_btn.pack()

    view_btn = tk.Button(text="View Passwords",  command= lambda : set_pin_window(win) )
    view_btn.pack()

    exit_btn = tk.Button(text="Exit", command=win.destroy)
    exit_btn.pack()

    if not hasattr(win, '_initialized'):
        win._initialized = True
        win.mainloop()

if __name__ == '__main__':
    main_window()


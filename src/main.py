# Simple GUI

from tkinter import *

# Create a window
root = Tk()

# Modify root window
root.title("Name of our tool")
root.geometry("400x400")

app = Frame(root)
app.grid()

label = Label(app, text="Some text")
label.grid()

button1 = Button(app, text="a button")
button1.grid()

button2 = Button(app)
button2.grid()
button2.configure(text="another button")

# Kick off main-event loop
root.mainloop()
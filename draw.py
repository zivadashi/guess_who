import tkinter as tk
import Analyze_networks

def draw_from_hid_data(canvas, points_list):
    cursor_x, cursor_y = 500, 500
    # Move to the starting point without drawing
    canvas.create_oval(cursor_x-2, cursor_y-2, cursor_x+2, cursor_y+2, fill='blue')

    for dx, dy in points_list:
        new_x = cursor_x + dx
        new_y = cursor_y + dy
        # Draw a line segment from current to new position
        canvas.create_line(cursor_x, cursor_y, new_x, new_y, fill='white', width=2)
        
        # Update current position
        cursor_x, cursor_y = new_x, new_y

    # Mark the end point
    canvas.create_oval(cursor_x-2, cursor_y-2, cursor_x+2, cursor_y+2, fill='red')

analyzer = Analyze_networks.AnalyzeNetwork("tablet.pcap")
simulated_hid_moves = analyzer.get_hid()

# Setup Tkinter window
root = tk.Tk()
root.title("HID Mouse Drawing Visualization")
canvas = tk.Canvas(root, bg='black', height=1000, width=2000)
canvas.pack()

# Draw the simulated HID path
draw_from_hid_data(canvas, simulated_hid_moves)

root.mainloop()

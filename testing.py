import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import ast
import os
from threading import Thread
import sys
import importlib.metadata  # For getting versions
import concurrent.futures  # For high-performance parallel scanning
import queue  # For thread-safe messaging
import time  # For animations/delays if needed


class RequirementsGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Requirements Generator v3.0 - Advanced Edition 🚀")
        self.root.geometry("800x600")
        self.root.minsize(600, 500)
        self.root.resizable(True, True)

        # Theme setup for polished look (dark/light mode)
        self.style = ttk.Style()
        self.theme = 'clam'  # Default theme
        self.style.theme_use(self.theme)
        self.dark_mode = False
        self.toggle_theme()  # Initialize theme

        # Center the window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

        # Main container
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

        # Title with emoji
        title_label = ttk.Label(main_frame, text="🛠️ Python Requirements Generator Pro",
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 20))

        # File/Folder selection frame
        file_frame = ttk.LabelFrame(main_frame, text="📂 Select Python Script or Folder", padding="5")
        file_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)

        self.file_path_var = tk.StringVar(value="No file or folder selected 📁")
        self.file_path_label = ttk.Label(file_frame, textvariable=self.file_path_var,
                                         wraplength=500, justify="left")
        self.file_path_label.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 5))

        # Buttons frame
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=1, column=0, columnspan=3, pady=(5, 0))
        btn_frame.columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.select_file_btn = ttk.Button(btn_frame, text="Browse File... 📄", command=self.select_file)
        self.select_file_btn.grid(row=0, column=0, padx=(0, 5), sticky=(tk.W, tk.E))

        self.select_folder_btn = ttk.Button(btn_frame, text="Browse Folder... 📂", command=self.select_folder)
        self.select_folder_btn.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))

        self.generate_btn = ttk.Button(btn_frame, text="Generate requirements.txt ⚙️",
                                       command=self.generate_requirements, state="disabled")
        self.generate_btn.grid(row=0, column=2, padx=5, sticky=(tk.W, tk.E))

        clear_btn = ttk.Button(btn_frame, text="Clear Output 🗑️", command=self.clear_output)
        clear_btn.grid(row=0, column=3, padx=5, sticky=(tk.W, tk.E))

        theme_btn = ttk.Button(btn_frame, text="Toggle Theme 🌗", command=self.toggle_theme)
        theme_btn.grid(row=0, column=4, padx=(5, 0), sticky=(tk.W, tk.E))

        # Advanced Options frame
        options_frame = ttk.LabelFrame(main_frame, text="⚙️ Advanced Options", padding="5")
        options_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        options_frame.columnconfigure(1, weight=1)

        self.include_versions_var = tk.BooleanVar(value=False)
        include_versions_check = ttk.Checkbutton(options_frame, text="Include versions (e.g., ==1.2.3) 📌",
                                                 variable=self.include_versions_var)
        include_versions_check.grid(row=0, column=0, sticky=(tk.W), pady=2)

        self.loose_versions_var = tk.BooleanVar(value=False)
        loose_versions_check = ttk.Checkbutton(options_frame, text="Use loose pinning (e.g., >=1.2.3) 🔓",
                                               variable=self.loose_versions_var)
        loose_versions_check.grid(row=1, column=0, sticky=(tk.W), pady=2)

        self.recursive_depth_var = tk.IntVar(value=0)
        ttk.Label(options_frame, text="Recursive depth (0 = unlimited) 🔍:").grid(row=2, column=0, sticky=(tk.W), pady=2)
        depth_entry = ttk.Entry(options_frame, textvariable=self.recursive_depth_var, width=5)
        depth_entry.grid(row=2, column=1, sticky=(tk.W), pady=2)

        self.exclude_modules_var = tk.StringVar(value="")
        ttk.Label(options_frame, text="Exclude modules (comma-separated) 🚫:").grid(row=3, column=0, sticky=(tk.W),
                                                                                   pady=2)
        exclude_entry = ttk.Entry(options_frame, textvariable=self.exclude_modules_var)
        exclude_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)

        self.custom_output_var = tk.BooleanVar(value=False)
        custom_output_check = ttk.Checkbutton(options_frame, text="Choose custom output path 💾",
                                              variable=self.custom_output_var)
        custom_output_check.grid(row=4, column=0, sticky=(tk.W), pady=2)

        # Note about drag and drop
        note_label = ttk.Label(main_frame,
                               text="💡 Pro Tip: Install 'tkinterdnd2' for drag-and-drop magic! Uncomment code to enable. 🪄",
                               foreground="gray")
        note_label.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))

        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="📊 Output Console", padding="5")
        output_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15,
                                                     font=('Consolas', 10), state=tk.DISABLED)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Progress bar with label
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))
        self.progress_label = ttk.Label(progress_frame, text="Status: Ready 🚦")
        self.progress_label.grid(row=0, column=0, sticky=(tk.W))
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate', length=400)
        self.progress.grid(row=0, column=1, padx=10, sticky=(tk.E))
        self.progress.grid_remove()  # Hidden by default

        # Status bar
        self.status_var = tk.StringVar(value="Welcome! Let's generate some requirements. 😎")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(5, 0))

        self.selected_path = None
        self.is_folder = False
        self.root.bind('<Configure>', self.on_resize)

        # Message queue for thread-safe updates
        self.message_queue = queue.Queue()
        self.root.after(100, self.process_queue)

        # Optional: Drag and drop setup (requires tkinterdnd2)
        # try:
        #     from tkinterdnd2 import DND_FILES, TkinterDnD
        #     self.root = TkinterDnD.Tk()  # Replace root
        #     self.root.drop_target_register(DND_FILES)
        #     self.root.dnd_bind('<<Drop>>', self.on_drop)
        #     self.root.dnd_bind('<<DragEnter>>', lambda e: e.widget.config(bg='lightblue'))
        #     self.root.dnd_bind('<<DragLeave>>', lambda e: e.widget.config(bg='white'))
        # except ImportError:
        #     pass

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.style.theme_use('clam')  # Placeholder; for real dark mode, use custom theme or library like ttkthemes
            self.root.config(bg='#333333')
            # Add more style configs for dark mode
        else:
            self.style.theme_use('clam')
            self.root.config(bg='white')
            # Reset to light

    def on_resize(self, event):
        new_width = self.root.winfo_width() - 150
        self.file_path_label.config(wraplength=new_width)

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select Python Script",
                                               filetypes=[("Python files", "*.py"), ("All files", "*.*")])
        if file_path:
            self.selected_path = file_path
            self.is_folder = False
            self.file_path_var.set(f"Selected file: {os.path.basename(file_path)} 📄 (Path: {file_path})")
            self.generate_btn.config(state="normal")
            self.status_var.set("File loaded! Ready to rock. 🎸")

    def select_folder(self):
        folder_path = filedialog.askdirectory(title="Select Folder with Python Scripts")
        if folder_path:
            self.selected_path = folder_path
            self.is_folder = True
            self.file_path_var.set(f"Selected folder: {os.path.basename(folder_path)} 📂 (Path: {folder_path})")
            self.generate_btn.config(state="normal")
            self.status_var.set("Folder selected! Let's scan deep. 🔦")

    # def on_drop(self, event):
    #     # Similar to previous, but enhanced with error handling

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_var.set("Output cleared! Fresh start. ✨")

    def update_status(self, message):
        self.message_queue.put(('status', message))

    def update_output(self, message, append=True):
        self.message_queue.put(('output', (message, append)))

    def update_progress(self, show=True):
        self.message_queue.put(('progress', show))

    def process_queue(self):
        try:
            while not self.message_queue.empty():
                msg_type, content = self.message_queue.get_nowait()
                if msg_type == 'status':
                    self.status_var.set(content)
                elif msg_type == 'output':
                    message, append = content
                    self.output_text.config(state=tk.NORMAL)
                    if not append:
                        self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, message + '\n')
                    self.output_text.see(tk.END)
                    self.output_text.config(state=tk.DISABLED)
                elif msg_type == 'progress':
                    if content:
                        self.progress.grid()
                        self.progress.start(10)
                    else:
                        self.progress.stop()
                        self.progress.grid_remove()
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def extract_imports_from_code(self, code):
        try:
            tree = ast.parse(code)
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
            return imports
        except SyntaxError:
            return set()

    def scan_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                code = f.read()
            return self.extract_imports_from_code(code)
        except Exception as e:
            self.update_output(f"⚠️ Skipped {os.path.basename(file_path)}: {e}", append=True)
            return set()

    def get_all_imports(self, path, max_depth):
        all_imports = set()
        exclude_modules = set(m.strip() for m in self.exclude_modules_var.get().split(',') if m.strip())
        depth = 0
        if self.is_folder:
            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
                futures = []
                for root_dir, dirs, files in os.walk(path):
                    if max_depth > 0 and depth > max_depth:
                        break
                    depth += 1
                    for file in files:
                        if file.endswith('.py'):
                            file_path = os.path.join(root_dir, file)
                            futures.append(executor.submit(self.scan_file, file_path))
                for future in concurrent.futures.as_completed(futures):
                    all_imports.update(future.result())
        else:
            all_imports = self.scan_file(path)
        # Exclude user-specified
        all_imports = {imp for imp in all_imports if imp not in exclude_modules}
        return all_imports

    def filter_third_party(self, imports):
        return [imp for imp in sorted(imports) if imp not in sys.stdlib_module_names and not imp.startswith('_')]

    def get_version(self, module_name, loose=False):
        try:
            version = importlib.metadata.version(module_name)
            return f">={version}" if loose else f"=={version}"
        except importlib.metadata.PackageNotFoundError:
            return None

    def generate_requirements_thread(self):
        try:
            self.update_status("Initiating scan... 🔍 Hold tight!")
            self.update_output("Starting analysis... 🧠", append=False)
            max_depth = self.recursive_depth_var.get()
            all_imports = self.get_all_imports(self.selected_path, max_depth)
            libraries = self.filter_third_party(all_imports)

            if not libraries:
                self.update_output(
                    "No third-party libs detected! 😅\n\nPro Tip: Check for dynamic imports or expand your scan. 🔄")
                self.update_status("Scan complete: All standard! 👍")
                return

            self.update_output(f"Found {len(libraries)} potential libs! 📚 Processing...")

            include_versions = self.include_versions_var.get()
            loose = self.loose_versions_var.get()
            req_lines = []
            missing_versions = []
            for lib in libraries:
                if include_versions:
                    version_spec = self.get_version(lib, loose)
                    if version_spec:
                        req_lines.append(f"{lib}{version_spec}")
                    else:
                        req_lines.append(lib)
                        missing_versions.append(lib)
                else:
                    req_lines.append(lib)

            req_content = '\n'.join(req_lines)

            # Custom output path
            if self.custom_output_var.get():
                output_path = filedialog.asksaveasfilename(title="Save requirements.txt", defaultextension=".txt",
                                                           filetypes=[("Text files", "*.txt")])
                if not output_path:
                    raise ValueError("Output path selection cancelled. 😔")
            else:
                if self.is_folder:
                    output_path = os.path.join(self.selected_path, 'requirements.txt')
                else:
                    output_path = os.path.join(os.path.dirname(self.selected_path), 'requirements.txt')

            with open(output_path, 'w') as f:
                f.write(req_content)

            self.update_output(
                f"🎉 Generated requirements.txt with {len(libraries)} libs:\n\n{req_content}\n\n💾 Saved to: {output_path}\n\n🚀 Install with: pip install -r requirements.txt")
            if missing_versions:
                self.update_output(
                    f"\n⚠️ Versions missing for: {', '.join(missing_versions)} (Install them for pinning! 🔧)",
                    append=True)

            self.update_status("Mission accomplished! 🎊 High-five! ✋")
            messagebox.showinfo("Success! 🏆", f"requirements.txt ready at:\n{output_path}")

        except Exception as e:
            error_msg = f"🚨 Oops! Error: {e}\n\nTry checking file permissions or syntax issues. 🛠️"
            self.update_output(error_msg)
            messagebox.showerror("Error! 😱", error_msg)
            self.update_status("Error occurred. Let's debug! 🐛")
        finally:
            self.update_progress(show=False)

    def generate_requirements(self):
        if not self.selected_path:
            messagebox.showerror("Error! 😠", "Select a file or folder first! 📂")
            return

        self.generate_btn.config(state="disabled")
        self.update_progress(show=True)
        self.clear_output()

        thread = Thread(target=self.generate_requirements_thread, daemon=True)
        thread.start()


if __name__ == "__main__":
    root = tk.Tk()
    app = RequirementsGeneratorGUI(root)
    root.mainloop()
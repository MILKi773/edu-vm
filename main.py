import argparse

from src.gui.main_gui import start_program
from src.web.app import start

def main(mode):
    if mode == "gui":
        start_program()
    elif mode == "web":
        start()
    else:
        print("Invalid mode")

if __name__ == "__main__":
    program = argparse.ArgumentParser(description='UVM')
    program.add_argument("-m", "--mode", choices=["gui", "web"], type=str, default="gui")

    args = program.parse_args()
    main(args.mode)
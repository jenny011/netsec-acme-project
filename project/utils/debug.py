ON = False

def debug_print(*args):
    if ON:
        for arg in args:
            print(arg)
        print()
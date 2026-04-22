import time
from core import AttackerCore  # Assuming you saved your merged class in core.py


class Attacker:
    def __init__(self):
        self.core = AttackerCore(
            on_receive_callback=self.handle_response,
            on_disconnect_callback=self.handle_disconnect
        )

    def handle_response(self, text):
        print(text, end="")

    def handle_disconnect(self):
        print("\nTarget dropped the connection.")
        self.core.disconnect()

    def run(self):
        print("\t\tTERMINAL\t\t")
        target = input("Enter Target Host: ")
        port = int(input("Enter Target Port: "))

        print(f"[*] Connecting to {target}:{port}...")
        success, msg = self.core.connect(target, port)

        if not success:
            print(f"[!] {msg}")
            return

        print("[*] Connection Established. Type 'exit' to quit.\n")

        # give background thread a split second to print banner
        time.sleep(0.5)

        # interactive Loop
        while self.core.connected:
            cmd = input("attacker@shadow:~$ ")

            if cmd.lower() in ['exit', 'quit']:
                self.core.disconnect()
                break

            # send command using core engine
            self.core.send_command(cmd)

            # wait to let the response print before asking for input again
            time.sleep(0.5)


if __name__ == "__main__":
    cli = Attacker()
    cli.run()
# Plays kiln-run's side of port 1024: accepts the guest's control connection on
# <uds>_1024, reads one frame, prints it, holds HOLD seconds, then closes.
import json, os, socket, struct, sys, time
uds, hold = sys.argv[1], float(sys.argv[2])
path = f"{uds}_1024"
try: os.unlink(path)
except FileNotFoundError: pass
l = socket.socket(socket.AF_UNIX); l.bind(path); l.listen(1)
print(f"host: listening on {path}", flush=True)
c, _ = l.accept(); t = time.time()
print(f"host: guest connected at {t:.3f}", flush=True)
hdr = c.recv(4, socket.MSG_WAITALL); n = struct.unpack("<I", hdr)[0]
body = c.recv(n, socket.MSG_WAITALL)
raw = hdr + body
print("host: frame bytes:", raw.hex(" "), flush=True)
print(f"host: len={n} type={body[0]} payload={json.loads(body[1:])}", flush=True)
time.sleep(hold); c.close(); print("host: closed control connection", flush=True)

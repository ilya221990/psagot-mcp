"""Load the installed read-only broker package independently of the entry point."""
import hashlib
from importlib import metadata, util
import sys

if metadata.version("mcp") != "2.2.0":
    raise RuntimeError("Install requirements.txt: this adapter requires the tested MCP SDK version")

source = metadata.distribution("spark-ordernet-mcp").locate_file("ordernet_mcp.py")
expected = "87fbd638c7e1cf2b7214eff601d9f131ebd8c326169f075fc9c9fabd2f06f92c"
if hashlib.sha256(source.read_bytes().rstrip()).hexdigest() != expected:
    raise RuntimeError("Broker source differs from the tested read-only version; install requirements.txt")

spec = util.spec_from_file_location("_psagot_broker", source)
module = util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
upstream = module.mcp

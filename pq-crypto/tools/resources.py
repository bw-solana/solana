#!/usr/bin/env python3
"""Read Linux process and host counters during an actual Agave PQ run.

Process CPU/RSS/IO are separate from host network/disk counters, which include
existing workloads. Unreadable values are null, never assumed to be zero.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import time

AUTHORIZED = {f"213.239.141.{n}" for n in (43, 44, 45, 46, 47, 48, 49, 32, 51, 31)}
SAMPLER = r'''
import hashlib,json,os,time
from pathlib import Path
cfg=CONFIG
errors=set()
exe_cache={}
def read(path):
 try:return Path(path).read_text()
 except OSError as error:errors.add(str(error));return None
def sample():
 try:pid=int(Path(cfg['pidfile']).read_text())
 except FileNotFoundError:pid=None
 root=Path('/proc')/str(pid)
 stat=read(root/'stat') if pid is not None and root.exists() else None;proc=None
 try:cmd=(root/'cmdline').read_bytes().split(b'\0') if stat else []
 except OSError as error:errors.add(str(error));cmd=[]
 argv=cmd[:-1] if cmd and cmd[-1]==b'' else cmd
 owned=(argv==[argument.encode() for argument in cfg['owned_command']]) if cfg.get('exact_owned_argv') else all(argument.encode() in cmd for argument in cfg['owned_command'])
 if stat and owned:
  fields=stat[stat.rfind(')')+2:].split()
  proc={'pid':pid,'cpu_seconds':(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK'),
        'rss_bytes':int(fields[21])*os.sysconf('SC_PAGE_SIZE'),'threads':int(fields[17]),'start_jiffies':int(fields[19])}
  io=read(root/'io')
  proc['io']={k:int(v) for k,v in (line.split(':') for line in io.splitlines())} if io else None
  try:
   exe=root/'exe';meta=exe.stat();identity=(meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns)
   if identity not in exe_cache:
    h=hashlib.sha384()
    with exe.open('rb') as stream:
     for chunk in iter(lambda:stream.read(1048576),b''):h.update(chunk)
    exe_cache.clear();exe_cache[identity]=h.hexdigest()
   proc['executable_sha384']=exe_cache[identity]
   proc['argv_sha384']=hashlib.sha384(b'\0'.join(argv)+b'\0').hexdigest()
   proc['configuration_sha384']=hashlib.sha384(Path(cfg['config']).read_bytes()).hexdigest() if cfg.get('config') else None
   if cfg.get('executable_sha384') and proc['executable_sha384']!=cfg['executable_sha384']:errors.add('owned executable digest changed')
   if cfg.get('configuration_sha384') and proc['configuration_sha384']!=cfg['configuration_sha384']:errors.add('owned configuration digest changed')
  except OSError as error:errors.add(str(error))
 if stat and not owned and not cfg['allow_starting']:errors.add('PID does not identify the owned experimental PQ process')
 cpu_lines=(read('/proc/stat') or '').splitlines()
 cpu=cpu_lines[0].split()[1:9] if cpu_lines else []
 network_text=read('/proc/net/dev');disk_text=read('/proc/diskstats')
 net={}
 for line in (network_text or '').splitlines()[2:]:
  name,data=line.split(':');name=name.strip();fields=data.split()
  # Bond/slave interfaces overlap. Account only interfaces without a master.
  if name=='lo' or (Path('/sys/class/net')/name/'master').exists():continue
  net[name]={'rx_bytes':int(fields[0]),'tx_bytes':int(fields[8]),
             'rx_drops':int(fields[3]),'tx_drops':int(fields[11])}
 disk={}
 for line in (disk_text or '').splitlines():
  p=line.split()
  if len(p)<14 or not (Path('/sys/block')/p[2]).exists() or p[2].startswith(('loop','ram','dm-','md')):continue
  disk[p[2]]={'read_bytes':int(p[5])*512,'write_bytes':int(p[9])*512,
              'read_ios':int(p[3]),'write_ios':int(p[7]),'busy_ms':int(p[12])}
 mem={}
 for line in (read('/proc/meminfo') or '').splitlines():
  k,v=line.split(':');mem[k]=int(v.split()[0])*1024
 return {'wall_seconds':time.time(),'monotonic_seconds':time.monotonic(),'process':proc,'cpu_jiffies':list(map(int,cpu)),
         'network':net,'disk':disk,'memory':mem,'errors':sorted(errors),
         'counter_available':{'network':network_text is not None,'disk':disk_text is not None}}
out=[sample()];deadline=time.monotonic()+cfg['duration']
print('AGAVE_PQ_SAMPLE_READY',flush=True)
print(json.dumps({'sample':out[0]}),flush=True)
time.sleep(1)
while time.monotonic()<deadline:
 out.append(sample());print(json.dumps({'sample':out[-1]}),flush=True);time.sleep(1)
print(json.dumps({'host':cfg['host'],'logical_cpus':os.cpu_count(),'samples':out}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--key", type=Path, default=Path.home()/"google_compute_engine")
    args = parser.parse_args()
    nodes = json.loads(args.manifest.read_text())["nodes"]
    args.output.mkdir(parents=True, exist_ok=True)
    for index in range(len(nodes)):
        (args.output/f"node-{index}.ready").unlink(missing_ok=True)
    def collect(pair):
        index, node = pair
        if args.remote and node["host"] not in AUTHORIZED:
            raise RuntimeError("unauthorized sampling host")
        cfg = {"host": node["host"], "pidfile":node.get("pidfile",str(Path(node["config"]).parent/"owned-validator.pid")),
            "owned_command":node.get("owned_command",[str(Path(node["config"]).parent/"ledger"),"--experimental-pq-config"]),
            "config":node.get("config"), "exact_owned_argv":node.get("exact_owned_argv",False),
            "executable_sha384":node.get("executable_sha384"), "configuration_sha384":node.get("configuration_sha384"),
            "allow_starting":node.get("kind") == "generator", "duration": args.duration}
        source = SAMPLER.replace("CONFIG", repr(cfg), 1)
        command = ["ssh", "-i", str(args.key), "-o", "BatchMode=yes", "sol@"+node["host"], "python3 -"] \
            if args.remote else ["python3", "-"]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        process.stdin.write(source)
        process.stdin.close()
        process.stdin = None
        marker = process.stdout.readline().strip()
        if marker != "AGAVE_PQ_SAMPLE_READY":
            stdout, stderr = process.communicate(timeout=args.duration+30)
            raise RuntimeError(f"sampler failed to become ready: {marker} {stderr}")
        (args.output/f"node-{index}.ready").write_text(str(time.time())+"\n")
        document = None
        live = args.output/f"node-{index}.live.json"
        with open(args.output/f"node-{index}.jsonl", "w") as raw:
            for line in process.stdout:
                observation = json.loads(line)
                if "sample" in observation:
                    raw.write(json.dumps(observation["sample"])+"\n")
                    raw.flush()
                    temporary = live.with_suffix(".tmp")
                    temporary.write_text(json.dumps(observation["sample"])+"\n")
                    temporary.replace(live)
                else:
                    document = observation
        _, stderr = process.communicate(timeout=30)
        if process.returncode:
            raise RuntimeError(f"sampler failed: {stderr}")
        if document is None:
            raise RuntimeError("sampler ended without its complete resource document")
        (args.output/f"node-{index}.json").write_text(json.dumps(document)+"\n")
        samples = document["samples"]
        first, last = samples[0], samples[-1]
        seconds = last["wall_seconds"] - first["wall_seconds"]
        process = [s["process"] for s in samples if s["process"] is not None]
        cpu_seconds = 0.0
        observed_process_seconds = 0.0
        process_io = {"read_bytes":0,"write_bytes":0}
        observed_io_pairs = 0
        for previous, current in zip(samples, samples[1:]):
            left, right = previous["process"], current["process"]
            if left is not None and right is not None and (left["pid"],left.get("start_jiffies")) == (right["pid"],right.get("start_jiffies")):
                delta = right["cpu_seconds"]-left["cpu_seconds"]
                if delta >= 0:
                    cpu_seconds += delta
                    observed_process_seconds += current["wall_seconds"]-previous["wall_seconds"]
                    if left.get("io") is not None and right.get("io") is not None:
                        observed_io_pairs += 1
                        for field in process_io:
                            process_io[field] += max(0,right["io"][field]-left["io"][field])
        cpu = cpu_seconds/observed_process_seconds if observed_process_seconds > 0 else None
        def rate(kind, field):
            if not first["counter_available"][kind] or not last["counter_available"][kind] or seconds <= 0:
                return None
            return sum(value[field]-first[kind].get(name, {}).get(field, value[field])
                for name, value in last[kind].items())/seconds
        disk_busy = {name: (value["busy_ms"]-first["disk"].get(name, value)["busy_ms"])/seconds/10
            for name, value in last["disk"].items()} if first["counter_available"]["disk"] and last["counter_available"]["disk"] else None
        return {"node": index, "host": node["host"], "observed_seconds": seconds,
            "kind":node.get("kind","validator"),
            "process_cpu_cores_mean": cpu,
            "process_io_bytes":process_io if observed_io_pairs > 0 else None,
            "process_observed_seconds": observed_process_seconds,
            "process_rss_first_bytes": process[0]["rss_bytes"] if process else None,
            "process_rss_last_bytes": process[-1]["rss_bytes"] if process else None,
            "process_rss_peak_bytes": max((p["rss_bytes"] for p in process), default=None),
            "process_threads_peak": max((p["threads"] for p in process), default=None),
            "host_network_rx_bytes_per_second": rate("network", "rx_bytes"),
            "host_network_tx_bytes_per_second": rate("network", "tx_bytes"),
            "host_disk_read_bytes_per_second": rate("disk", "read_bytes"),
            "host_disk_write_bytes_per_second": rate("disk", "write_bytes"),
            "host_disk_busy_percent": disk_busy,
            "host_memory_available_min_bytes": min(s["memory"]["MemAvailable"] for s in samples) if all("MemAvailable" in s["memory"] for s in samples) else None,
            "errors": sorted({error for s in samples for error in s["errors"]})}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        values = list(pool.map(collect, enumerate(nodes)))
    summary = {"actual_agave_validator": True,
        "scope": "CPU/RSS/IO are per owned validator or generator; network/disk/memory are host totals including other workloads",
        "nodes": values}
    (args.output/"summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

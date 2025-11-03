const dns = require('dns');
const net = require('net');
const { argv } = require('process');

function parseArgs() {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--host') {
      args.host = argv[++i];
    } else if (a === '-p' || a === '--ports') {
      args.ports = argv[++i];
    } else if (a === '-c' || a === '--concurrency') {
      args.concurrency = Number(argv[++i]);
    } else if (a === '-t' || a === '--timeout') {
      args.timeout = Number(argv[++i]);
    } else if (a === '-v' || a === '--verbose') {
      args.verbose = true;
    } else if (a === '--help') {
      args.help = true;
    } else if (a === '--service-detect') {
      args.serviceDetect = true;
    } else if (a === '--json') {
      args.json = true;
    } else {

    }
  }
  return args;
}

function printHelp() {
  console.log(`
Usage: node port-scanner.js --host <target> [options]

Options:
  -h, --host <target>         target IP or hostname (required)
  -p, --ports <list|range>    ports like "22,80,443" or "1-1024" (default: 1-1024)
  -c, --concurrency <num>     number of simultaneous connections (default: 200)
  -t, --timeout <ms>          per-port timeout in ms (default: 2000)
  --service-detect            run simple service detection using common ports
  --json                      output results as JSON
  --help                      show this help

Examples:
  node nmap-js-scanner.js --host 192.168.1.1 --ports 22-1024 --concurrency 200 --timeout 2000
  node nmap-js-scanner.js -h example.com -p 80,443,8080 -c 50
`);
}

function expandPorts(portsArg) {
  if (!portsArg) return range(1, 1024);
  const parts = portsArg.split(',');
  const set = new Set();
  parts.forEach(p => {
    p = p.trim();
    if (p.includes('-')) {
      const [a, b] = p.split('-').map(Number);
      for (let x = Math.max(1, a); x <= Math.min(65535, b); x++) set.add(x);
    } else {
      const n = Number(p);
      if (n >= 1 && n <= 65535) set.add(n);
    }
  });
  return Array.from(set).sort((a, b) => a - b);
}

function range(a, b) {
  const out = [];
  for (let i = a; i <= b; i++) out.push(i);
  return out;
}

const COMMON_SERVICES = {
  20: 'ftp-data',
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  111: 'rpcbind',
  139: 'netbios-ssn',
  143: 'imap',
  443: 'https',
  445: 'microsoft-ds',
  993: 'imaps',
  995: 'pop3s',
  3306: 'mysql',
  3389: 'ms-wbt-server',
  5900: 'vnc',
  8080: 'http-proxy'
};

class Semaphore {
  constructor(max) {
    this.max = max;
    this.current = 0;
    this.queue = [];
  }
  acquire() {
    return new Promise(resolve => {
      if (this.current < this.max) {
        this.current++;
        resolve();
      } else {
        this.queue.push(resolve);
      }
    });
  }
  release() {
    this.current = Math.max(0, this.current - 1);
    if (this.queue.length > 0) {
      const resolve = this.queue.shift();
      this.current++;
      resolve();
    }
  }
}

async function scanPort(host, port, timeout) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let isOpen = false;
    let banner = null;
    let finished = false;

    socket.setTimeout(timeout);

    socket.connect(port, host, () => {
      isOpen = true;
  
    });

    socket.on('data', data => {
      if (!banner) banner = data.toString('utf8', 0, 512).replace(/\r/g, '');
  
      socket.destroy();
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', err => {
    
    });

    socket.on('close', hadError => {
      if (finished) return;
      finished = true;
      resolve({ port, open: isOpen, banner });
    });

  });
}

async function resolveHost(target) {
  return new Promise(resolve => {
    dns.lookup(target, { all: false }, (err, address, family) => {
      if (err) return resolve({ error: err.message });
      resolve({ address, family });
    });
  });
}

async function reverseDns(ip) {
  return new Promise(resolve => {
    dns.reverse(ip, (err, hostnames) => {
      if (err) return resolve(null);
      resolve(hostnames && hostnames.length ? hostnames[0] : null);
    });
  });
}

async function runScan(options) {
  const target = options.host;
  const timeout = options.timeout || 2000;
  const concurrency = options.concurrency || 200;
  const ports = expandPorts(options.ports);

  const sem = new Semaphore(concurrency);

  const resolved = await resolveHost(target);
  if (resolved.error) {
    console.error('Host resolution failed:', resolved.error);
    process.exit(2);
  }
  const ip = resolved.address;
  const rdns = await reverseDns(ip);

  if (!options.json) {
    console.log(`Scanning ${target} (${ip}) - ${ports.length} ports, concurrency=${concurrency}, timeout=${timeout}ms`);
    if (rdns) console.log(`Reverse DNS: ${rdns}`);
    console.log('—————————————————');
  }

  const results = [];

  const tasks = ports.map(port => (async () => {
    await sem.acquire();
    try {
      if (options.verbose) process.stdout.write(`Scanning ${port}... `);
      const res = await scanPort(ip, port, timeout);
      if (res.open) {
        // attach service guess
        res.service = COMMON_SERVICES[port] || null;
        if (!options.json) {
          console.log(`${port}\topen\t${res.service || '-'}${res.banner ? '\t' + (res.banner.split('\n')[0]) : ''}`);
        }
        results.push(res);
      } else {
        if (options.verbose) process.stdout.write('closed\n');
      }
    } finally {
      sem.release();
    }
  })());

  await Promise.all(tasks);

  if (options.json) {
    const output = { target, ip, rdns, scannedPorts: ports.length, openPorts: results };
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log('—————————————————');
    console.log(`Scan complete. ${results.length} open port(s) found.`);
  }
}

(async () => {
  const args = parseArgs();
  if (args.help || !args.host) {
    printHelp();
    process.exit(0);
  }
  try {
    await runScan({ host: args.host, ports: args.ports, concurrency: args.concurrency, timeout: args.timeout, verbose: args.verbose, serviceDetect: args.serviceDetect, json: args.json });
  } catch (e) {
    console.error('Fatal error:', e);
  }
})();

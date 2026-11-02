#!/usr/bin/env python3
# Reference location databases and their expected answers, for
# tests/test-geodb.c and tests/test-geodb.sh (1.0.7 threat intel,
# round 2).
#
# Written with python3-location (libloc's own Python binding): the
# files come from libloc's writer, the answers from libloc's reader.
# StockFW's reader (src/core/fs-geodb.c) shares no code with libloc, so
# agreeing with these answers is agreeing with an independent
# implementation.
#
#   geodb-fixtures.py <outdir> <key1.pem> <key2.pem> [--big]
#   geodb-fixtures.py --reference <db> <outdir> <name> <seed> <count>
#       expected answers for a database written elsewhere (IPFire's):
#       <name>.lookup.tsv and <name>.enum.txt, as below
#
# libloc stamps a database with time(NULL); run this under the
# LD_PRELOAD shim test-geodb.sh builds (FAKE_TIME=<unix seconds>) to
# give each file a fixed creation time.  The script sets FAKE_TIME per
# file itself.  --big writes a larger random database (not committed).
#
# Output, per database <name>.db:
#   <name>.lookup.tsv  address, status (found / none / ref-error),
#                      network, country, ASN, flags, AS name as shown
#   <name>.enum.txt    "filter <spec>" lines, each followed by the
#                      fewest CIDR prefixes covering what libloc's
#                      flattened search returns for that filter
#   <name>.meta.txt    creation time, vendor, description, licence,
#                      countries and AS names

import ipaddress
import os
import random
import subprocess
import sys
import unicodedata

import location

FLAGS = (location.NETWORK_FLAG_ANONYMOUS_PROXY,
         location.NETWORK_FLAG_SATELLITE_PROVIDER,
         location.NETWORK_FLAG_ANYCAST,
         location.NETWORK_FLAG_DROP)

T0 = 1700000000          # 2023-11-14 22:13:20 UTC


def display(text):
    """fs-geodb's display rule: control and format characters become ?"""
    return "".join("?" if unicodedata.category(c) in ("Cc", "Cf") else c
                   for c in text)


def display_nl(text):
    """The same, keeping newlines (the description)"""
    return "".join("?" if unicodedata.category(c) in ("Cc", "Cf") and
                   c != "\n" else c for c in text)


def esc(text):
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def write_db(path, keys, created, spec):
    """Run a child with FAKE_TIME set so libloc's time(NULL) is fixed."""
    env = dict(os.environ, FAKE_TIME=str(created))
    subprocess.run([sys.executable, "-I", __file__, "--write", path] + keys,
                   input=repr(spec).encode(), env=env, check=True)


def do_write(path, keys):
    spec = eval(sys.stdin.read())          # our own repr() from above
    w = location.Writer(*[open(k, "rb") for k in keys])
    w.vendor = spec["vendor"]
    w.description = spec["description"]
    w.license = spec["license"]
    for number, name in spec["ases"]:
        a = w.add_as(number)
        a.name = name
    for code, continent, name in spec["countries"]:
        c = w.add_country(code)
        c.continent_code = continent
        c.name = name
    for net, cc, asn, flags in spec["networks"]:
        n = w.add_network(net)
        if cc:
            n.country_code = cc
        if asn:
            n.asn = asn
        for f in FLAGS:
            if flags & f:
                n.set_flag(f)
    w.write(path)


# ---- the databases --------------------------------------------------

def small_spec():
    return {
        "vendor": "StockFW test vendor",
        "description": "Reference database for the StockFW tests.\n"
                       "Written by libloc's writer.",
        "license": "CC0-1.0",
        "ases": [
            (64500, "Example One"),
            (64501, "Example Two GmbH"),
            (64502, "T\u00e9st \u00dcn\u00efcode"),
            (64504, "Sat\x07Net"),                  # a BEL in a name
            (64505, "\u202eEvil Corp"),             # a bidi override
            (64506, "Adjacent Halves"),
            (2147483647, "Largest the binding takes"),
        ],
        "countries": [
            ("DE", "EU", "Germany"),
            ("FR", "EU", "France"),
            ("GB", "EU", "United Kingdom"),
            ("IT", "EU", "Italy"),
            ("JP", "AS", "Japan"),                  # no networks
            ("NL", "EU", "Netherlands"),
            ("US", "NA", "United States"),
        ],
        "networks": [
            # three levels of nesting, each a different owner
            ("10.0.0.0/8", "DE", 64500, 0),
            ("10.1.0.0/16", "US", 64501, location.NETWORK_FLAG_ANYCAST),
            ("10.1.2.0/24", "FR", 64502,
             location.NETWORK_FLAG_ANONYMOUS_PROXY | location.NETWORK_FLAG_DROP),
            # no country, an AS that has no entry
            ("10.1.2.128/25", "", 64503, 0),
            # the same owner nested: enumerations merge it away
            ("10.200.0.0/14", "DE", 64500, 0),
            ("192.0.2.0/24", "NL", 64504,
             location.NETWORK_FLAG_SATELLITE_PROVIDER),
            ("198.51.100.7/32", "GB", 64505, 0),
            # two adjacent halves: one /24 in an enumeration
            ("203.0.113.0/25", "IT", 64506, 0),
            ("203.0.113.128/25", "IT", 64506, 0),
            ("255.255.255.255/32", "JP", 2147483647, 0),
            ("2001:db8::/32", "US", 64501, 0),
            ("2001:db8:1::/48", "DE", 64500, location.NETWORK_FLAG_DROP),
            ("2001:db8:1:2::/64", "FR", 64502, 0),
            ("2001:db8:1:2::1/128", "GB", 64505, 0),
            ("2001:db8:ffff::/48", "US", 64501, 0),
            ("2c0f:f000::/20", "NL", 0, location.NETWORK_FLAG_ANYCAST),
            ("ffff:ffff:ffff:ffff::/64", "IT", 64506, 0),
        ],
    }


CODES = ["AT", "BE", "CH", "DE", "ES", "FR", "GB", "IT", "NL", "US"]


def random_spec(seed, count):
    rnd = random.Random(seed)
    asns = list(range(65000, 65040))
    named = asns[:30]                       # ten ASes have no entry
    spec = {
        "vendor": "StockFW random %d" % seed,
        "description": "Random reference database (seed %d)." % seed,
        "license": "CC0-1.0",
        "ases": [(a, "Random AS %d" % a) for a in named],
        "countries": [(c, "EU" if c != "US" else "NA", "Country " + c)
                      for c in CODES],
        "networks": [],
    }
    seen = set()

    def owner():
        cc = rnd.choice(CODES + [""])
        asn = rnd.choice(asns + [0])
        flags = 0
        for f in FLAGS:
            if rnd.random() < 0.08:
                flags |= f
        return cc, asn, flags

    tops = []
    while len(spec["networks"]) < count:
        roomy = [t for t in tops if t.max_prefixlen - t.prefixlen >= 2]
        if roomy and rnd.random() < 0.6:
            # a subnet of an earlier network, a different owner
            parent = rnd.choice(roomy)
            extra = rnd.randint(1, min(12, parent.max_prefixlen -
                                       parent.prefixlen))
            subs = list(parent.subnets(prefixlen_diff=extra)) \
                if extra <= 6 else None
            if subs:
                net = rnd.choice(subs)
            else:
                size = parent.num_addresses >> extra
                start = int(parent.network_address) + \
                    rnd.randrange(parent.num_addresses // size) * size
                net = ipaddress.ip_network((start, parent.prefixlen + extra))
        elif rnd.random() < 0.5:
            plen = rnd.randint(8, 30)
            start = rnd.randrange(1 << 32) & ~((1 << (32 - plen)) - 1)
            net = ipaddress.IPv4Network((start, plen))
            if net.is_private or net.is_multicast or net.is_reserved or \
               net.is_loopback or net.is_link_local or net.is_unspecified:
                continue
        else:
            plen = rnd.randint(16, 64)
            start = (0x2000 << 112) | rnd.randrange(1 << 125)
            start &= ~((1 << (128 - plen)) - 1)
            net = ipaddress.IPv6Network((start, plen))
        if str(net) in seen:
            continue
        seen.add(str(net))
        tops.append(net)
        cc, asn, flags = owner()
        spec["networks"].append((str(net), cc, asn, flags))
    return spec


def edge_spec():
    return {
        "vendor": "edge", "description": "edge", "license": "CC0-1.0",
        "ases": [(1, "One"), (2, "Two"), (3, "Three"), (4, "Four")],
        "countries": [("DE", "EU", "Germany"), ("FR", "EU", "France"),
                      ("IT", "EU", "Italy"), ("US", "NA", "United States")],
        "networks": [
            ("::/8", "US", 1, 0),            # covers ::ffff:0:0/96 too
            ("0.0.0.0/0", "DE", 2, 0),       # all of IPv4
            ("1.2.3.4/32", "FR", 3, 0),
            ("2001:db8::1/128", "IT", 4, 0),
        ],
    }


def edge6_spec():
    return {
        "vendor": "edge6", "description": "edge6", "license": "CC0-1.0",
        "ases": [(1, "One"), (5, "Five")],
        "countries": [("US", "NA", "United States")],
        "networks": [
            ("::/0", "US", 1, 0),            # IPv6 only, never IPv4
            ("1.0.0.0/8", "", 5, 0),
        ],
    }


def empty_spec():
    return {"vendor": "", "description": "", "license": "", "ases": [],
            "countries": [], "networks": []}


# ---- expected answers -------------------------------------------------

def addresses(spec, rnd, extra):
    out = []
    for net, _cc, _asn, _flags in spec["networks"]:
        n = ipaddress.ip_network(net)
        first = int(n.network_address)
        last = int(n.broadcast_address)
        top = (1 << n.max_prefixlen) - 1
        for v in (first, last, first - 1, last + 1,
                  first + (last - first) // 2):
            if 0 <= v <= top:
                out.append(str(ipaddress.ip_address(v) if n.version == 6
                               else ipaddress.IPv4Address(v)))
        if n.version == 4:
            out.append("::ffff:" + str(n.network_address))
    for _ in range(extra):
        if rnd.random() < 0.5:
            out.append(str(ipaddress.IPv4Address(rnd.randrange(1 << 32))))
        else:
            out.append(str(ipaddress.IPv6Address(
                (0x2000 << 112) | rnd.randrange(1 << 125))))
    out += ["0.0.0.0", "255.255.255.255", "::", "::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:0.0.0.0",
            "::ffff:255.255.255.255", "10.255.255.255", "11.0.0.0"]
    seen, uniq = set(), []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq


def flags_of(n):
    v = 0
    for f in FLAGS:
        if n.has_flag(f):
            v |= f
    return v


def expected_lookups(db, addrs, out):
    with open(out, "w") as f:
        for a in addrs:
            try:
                n = db.lookup(a)
                status = "found" if n else "none"
            except ValueError:
                # libloc cannot name an IPv6 network for an IPv4
                # address (prefix underflow); fs-geodb finds none
                n, status = None, "ref-error"
            except OSError:
                # the binding's "nothing found" (errno ENOENT, or
                # whatever errno was left over)
                n, status = None, "none"
            if not n:
                f.write("%s\t%s\t\t\t0\t0\t\n" % (a, status))
                continue
            name = ""
            if n.asn:
                a_s = db.get_as(n.asn)
                name = display(a_s.name) if a_s else ""
            f.write("%s\tfound\t%s\t%s\t%d\t%d\t%s\n" % (
                a, n, n.country_code or "", n.asn or 0, flags_of(n),
                esc(name)))


def collapse(nets):
    v4, v6 = [], []
    mapped = ipaddress.ip_network("::ffff:0:0/96")
    for n in nets:
        n = ipaddress.ip_network(str(n))
        if n.version == 4:
            v4.append(n)
        elif not n.overlaps(mapped):
            v6.append(n)
        elif n != mapped and mapped.subnet_of(n):
            v6 += list(n.address_exclude(mapped))
    return [str(n) for n in ipaddress.collapse_addresses(v4)] + \
           [str(n) for n in ipaddress.collapse_addresses(v6)]


def filters_for(spec):
    ccs = sorted({cc for _n, cc, _a, _f in spec["networks"] if cc})
    asns = sorted({a for _n, _c, a, _f in spec["networks"] if a})
    out = []
    for cc in ccs:
        out.append(([cc], [], 0))
    for a in asns[:12]:
        out.append(([], [a], 0))
    for f in FLAGS:
        out.append(([], [], f))
    if len(ccs) >= 2 and len(asns) >= 2:
        out.append((ccs[:2], asns[-2:], location.NETWORK_FLAG_DROP))
    out.append((ccs, [], 0))
    out.append(([], [], 0))
    return out


def spec_text(ccs, asns, flags):
    return "cc=%s asn=%s flags=%d" % (",".join(ccs) or "-",
                                      ",".join(map(str, asns)) or "-", flags)


def expected_enum(db, spec, out):
    with open(out, "w") as f:
        for ccs, asns, flags in filters_for(spec):
            nets = []
            if ccs or asns or flags:
                kw = {"flatten": True}
                if ccs:
                    kw["country_codes"] = ccs
                if asns:
                    kw["asns"] = asns
                if flags:
                    kw["flags"] = flags
                try:
                    nets = list(db.search_networks(**kw))
                except ValueError:
                    # libloc cannot flatten a tree whose IPv6 networks
                    # cover IPv4 space; test-geodb.c checks those by hand
                    f.write("filter %s ref-error\n" %
                            spec_text(ccs, asns, flags))
                    continue
            f.write("filter %s\n" % spec_text(ccs, asns, flags))
            for p in collapse(nets):
                f.write(p + "\n")


def expected_meta(db, spec, out):
    with open(out, "w") as f:
        f.write("created_at\t%d\n" % db.created_at)
        f.write("vendor\t%s\n" % esc(display(db.vendor or "")))
        f.write("description\t%s\n" % esc(display_nl(db.description or "")))
        f.write("license\t%s\n" % esc(display(db.license or "")))
        for c in sorted(db.countries, key=lambda c: c.code):
            f.write("country\t%s\t%s\t%s\n" % (c.code, c.continent_code or "",
                                               esc(display(c.name))))
        for a in sorted(db.ases, key=lambda a: a.number):
            f.write("as\t%d\t%s\n" % (a.number, esc(display(a.name or ""))))


def emit(outdir, name, keys, created, spec, rnd, extra):
    path = os.path.join(outdir, name + ".db")
    write_db(path, keys, created, spec)
    db = location.Database(path)
    expected_lookups(db, addresses(spec, rnd, extra),
                     os.path.join(outdir, name + ".lookup.tsv"))
    expected_enum(db, spec, os.path.join(outdir, name + ".enum.txt"))
    expected_meta(db, spec, os.path.join(outdir, name + ".meta.txt"))


REAL_FILTERS = [(["LI"], [], 0), (["VA"], [], 0), (["IS"], [], 0),
                (["NZ"], [], 0), ([], [15169], 0), ([], [13335], 0),
                ([], [3320], 0)] + [([], [], f) for f in FLAGS] + \
               [(["LI", "VA"], [13335], location.NETWORK_FLAG_DROP)]


def reference(path, outdir, name, seed, count):
    """Expected answers for a database we did not write (the real one):
    the boundaries of a sample of its networks, random addresses, and a
    few filters."""
    db = location.Database(path)
    rnd = random.Random(seed)
    addrs = []
    step = max(1, count // 4)
    for i, n in enumerate(db.networks):
        if rnd.randrange(1 << 30) % 997 != 0:
            continue
        net = ipaddress.ip_network(str(n))
        top = (1 << net.max_prefixlen) - 1
        for v in (int(net.network_address), int(net.broadcast_address),
                  int(net.network_address) - 1,
                  int(net.broadcast_address) + 1):
            if 0 <= v <= top:
                addrs.append(str(ipaddress.ip_address(v) if net.version == 6
                                 else ipaddress.IPv4Address(v)))
        if len(addrs) >= step * 4:
            break
    spec = {"networks": []}
    more = addresses(spec, rnd, count)
    seen, uniq = set(), []
    for a in addrs + more:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    expected_lookups(db, uniq, os.path.join(outdir, name + ".lookup.tsv"))
    global filters_for
    filters_for = lambda _spec: REAL_FILTERS
    expected_enum(db, spec, os.path.join(outdir, name + ".enum.txt"))


def main():
    if sys.argv[1] == "--write":
        do_write(sys.argv[2], sys.argv[3:])
        return
    if sys.argv[1] == "--reference":
        reference(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]),
                  int(sys.argv[6]))
        return
    outdir, k1, k2 = sys.argv[1:4]
    big = "--big" in sys.argv[4:]
    os.makedirs(outdir, exist_ok=True)
    rnd = random.Random(1077)
    small = small_spec()
    emit(outdir, "small", [k1], T0, small, rnd, 40)
    write_db(os.path.join(outdir, "small-two.db"), [k1, k2], T0, small)
    write_db(os.path.join(outdir, "small-older.db"), [k1], T0 - 1, small)
    write_db(os.path.join(outdir, "small-newer.db"), [k1], T0 + 86400, small)
    emit(outdir, "random", [k1], T0, random_spec(1077, 300), rnd, 300)
    emit(outdir, "edge", [k1], T0, edge_spec(), rnd, 20)
    emit(outdir, "edge6", [k1], T0, edge6_spec(), rnd, 20)
    emit(outdir, "empty", [k1], T0, empty_spec(), rnd, 10)
    if big:
        emit(outdir, "big", [k1], T0, random_spec(2077, 6000), rnd, 20000)


if __name__ == "__main__":
    main()

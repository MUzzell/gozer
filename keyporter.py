import requests, pdb, re, sys
from keys import KeyManager, PgpKeyError

dom = ['com', 'co', 'gov', 'net', 'org']

id_re = re.compile("^pub:([^:]+)")


if len(sys.argv) < 2:
    sys.stderr.write("keyporter: grab keys from an sks keyserver\nUsage:\n    keyporter.py HOST PORT=11371\n")
    sys.exit()

host = sys.argv[1]
port = sys.argv[2] if len(sys.argv) > 2 else '11371'

sys.stderr.write("host: %s\n" % host)
sys.stderr.write("port: %s\n" % port)

total = 0
for d in dom:
    response = requests.get("http://%s:%s/pks/lookup?search=%s&options=mr&op=index" % (host, port, d) )
    
    if response.status_code != 200:
        continue


    keym = KeyManager()

    sub_total = 0
    for key_id in [id_re.match(x).group(1) for x in response.text.split('\n')  if id_re.match(x) is not None]: 
        cert_response = requests.get("http://%s:%s/pks/lookup?search=0x%s&op=get" % (host, port, key_id))
    
        if cert_response.status_code != 200:
            continue

        cert_response_text = cert_response.text.split("\n")

        cert_start = [x for x in range(0, len(cert_response_text)) if cert_response_text[x].startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")][0]
        cert_end = [x for x in range(0, len(cert_response_text)) if cert_response_text[x].startswith("-----END PGP PUBLIC KEY BLOCK-----")][0] + 1

        cert = "\n".join(cert_response_text[cert_start:cert_end]).strip()

        try:
            keym.add(str(cert))
            sub_total += 1
        except PgpKeyError:
            print "error importing key"
            pass
    print "%d keys processed for '%s'" % (sub_total, d)
    total += sub_total

print "%d keys processed" % total

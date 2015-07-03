import os, pdb, datetime, sys
from flask import Flask, make_response, render_template, request, abort
from keys import KeyManager, PgpKeyError

app = Flask(__name__)
app.debug = True

@app.errorhandler(500)
def error_500(e):
    return render_template("error_500.html"), 500

@app.errorhandler(400)
def error_400(e):
    return render_template("error_400.html"), 400

@app.errorhandler(404)
def error_404(e):
    return render_template("error_404.html"), 404

@app.route("/keyring")
def keyring():
    
    keym = KeyManager()
    
    keys = keym.export_keyring()

    response = make_response(keys)
    response.headers['Content-Type'] = 'application/pkix-cert'

    return response

@app.template_filter('datetime')
def format_timestamp(value):
    return datetime.datetime.fromtimestamp(value).strftime("%Y-%m-%d")    


@app.template_filter('escape_nonascii')
def escape_nonascii(value):
    escaped = ''
    for x in value:
        escaped += '%%%s%%' % format(ord(x), "x") if ord(x) > 128 else x
    return escaped

app.jinja_env.globals.update(escape_nonascii=escape_nonascii)

@app.route("/pks/lookup", endpoint='lookup')
def pks_lookup():
    op = ''

    if 'op' not in request.args:
        return abort(500)
    else:
        op = request.args.get('op')

    search = None
    if 'search' not in request.args:
        return abort(500)
    search = request.args.get('search')

    options = None
    if 'options' in request.args:
        options = request.args.get('options')

    try:
        search = str(search)
    except UnicodeError:
        return abort(400)

    fingerprint = request.args.get('fingerprint') == 'on' if 'fingerprint' in request.args else False
    exact = request.args.get('exact') == 'on' if 'exact' in request.args else False
    m = KeyManager()
    if op == 'index':
        return lookup_index(m, search, fingerprint, options)
    elif op == 'vindex':
        return lookup_vindex(m, search, fingerprint, options)
    elif op == 'get':
        return lookup_get(m, search)
    else:
        return abort(500)
                       
def lookup_index(keym, search, fingerprint, options):
    try:
        keys = keym.search(search)
        if keys is None or len(keys) == 0:
            return abort(404)
        
        if options == 'mr':
            response = make_response(render_template("index.txt", key_info = {'keys' : keys, 'total' : len(keys)}))
            response.headers['Content-Type'] = 'text/plain'
            return response
        else:
            return render_template("index.html", key_info = { 'keys' : keys, 'total' : len(keys), 'search_term' : search, 'fingerprint' : fingerprint})

    except PgpKeyError:
        return abort(404)

#currently not implemented
def lookup_vindex(keym, search, fingerprint):
    abort(500)
'''
    try:
        keys = keym.search(search, True)
        if keys is None or len(keys) == 0:
            return abort(404)
        if options == 'mr':
            response = make_response(render_template("index.txt", key_info = {'keys' : keys, 'total' : len(keys)}))
            response.headers['Content-Type'] = 'text/plain'
            return response
        else:
            return render_template("vindex.html", key_info = { 'keys' : keys, 'total' : len(keys), 'search_term' : search, 'fingerprint' : fingerprint })
    except PgpKeyError:
        return abort(404)
'''
def lookup_get(keym, search):
    try:
        key = keym.get(search)
        response = make_response(render_template("get_key.html", key_info = { 'key' : key, 'key_id' : search }))
        return response
    except PgpKeyError:
        return abort(404)

@app.route("/pks/add", methods=['POST'])
def pks_add():
    if 'keytext' not in request.form or request.form['keytext'] is None:
        return abort(500)

    key = str(request.form['keytext'])
    keym = KeyManager()
    try:
        added = keym.add(key)
        return render_template("add_key.html", added = added), 200
    except PgpKeyError:
        return abort(400)
       
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=11371)

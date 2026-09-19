// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
// Author Claude/bentzn
//
// Raposza OIDC - the web UI's whole script.
//
// IT IS A CLIENT OF THE JSON API AND HAS NO OTHER WAY IN. Every value on the
// screen came from a call below; nothing is computed here that the server
// could be asked for. That is what keeps this page from becoming a second
// source of truth about what the service is doing - `raposza_oidc.md` 8.
//
// No framework, no build step - D-774.

'use strict';

// ------------------------------------------------------------------ plumbing

function el(id) {
    return document.getElementById(id);
}


function show(node, flagOn) {
    node.classList.toggle('hidden', !flagOn);
}


function clear(node) {
    while (node.firstChild)
        node.removeChild(node.firstChild);
}


// EVERY CELL GOES THROUGH HERE, so a key id or a claim that happens to look
// like markup is text and never markup.
function cell(tr, strValue, strClass) {
    const td = document.createElement('td');
    if (strClass)
        td.className = strClass;
    td.appendChild(document.createTextNode(
            strValue === null || strValue === undefined ? '-' : String(strValue)));
    tr.appendChild(td);
    return td;
}


function row(tbody) {
    const tr = document.createElement('tr');
    tbody.appendChild(tr);
    return tr;
}


function oops(strMessage) {
    const node = el('oops');
    node.textContent = strMessage || '';
    show(node, !!strMessage);
}


// THE ONE PLACE A 401 IS HANDLED. Every guarded call comes through here, so
// the gate appears wherever the session expired rather than in five places.
async function api(strPath, objOpts) {
    const opts = Object.assign({credentials: 'same-origin'}, objOpts || {});
    if (opts.body !== undefined && typeof opts.body !== 'string') {
        opts.body = JSON.stringify(opts.body);
        opts.headers = Object.assign({'Content-Type': 'application/json'},
                opts.headers || {});
    }

    const res = await fetch(strPath, opts);
    if (res.status === 401) {
        showGate();
        throw new Error('sign in first');
    }

    let objBody = null;
    const strType = res.headers.get('content-type') || '';
    if (strType.indexOf('json') >= 0)
        objBody = await res.json();

    if (!res.ok) {
        const strWhy = objBody && (objBody.error_description || objBody.error);
        throw new Error(strWhy || (res.status + ' ' + res.statusText));
    }
    return objBody;
}


function showGate() {
    show(el('gate'), true);
    show(el('app'), false);
}


function showApp() {
    show(el('gate'), false);
    show(el('app'), true);
}


// --------------------------------------------------------------------- tabs

const mapLoad = {};

// Two cards belong to one tab, so the tab owns a LIST of sections rather than
// a section owning a tab name.
const mapSection = {
    overview: ['tab-overview'],
    keys: ['tab-keys', 'tab-keys-add'],
    users: ['tab-users', 'tab-users-add'],
    clients: ['tab-clients', 'tab-clients-add'],
    mint: ['tab-mint'],
    inspect: ['tab-inspect']
};


function selectTab(strName) {
    const lstBtn = document.querySelectorAll('#tabs .seg-btn[data-tab]');
    for (let idx = 0; idx < lstBtn.length; idx++)
        lstBtn[idx].classList.toggle('active', lstBtn[idx].dataset.tab === strName);

    Object.keys(mapSection).forEach(function (strTab) {
        mapSection[strTab].forEach(function (strId) {
            show(el(strId), strTab === strName);
        });
    });

    oops('');
    if (mapLoad[strName])
        mapLoad[strName]().catch(ex => oops(ex.message));
}


// ----------------------------------------------------------------- overview

mapLoad.overview = async function () {
    const obj = await api('/api/ui/overview');

    const tbody = el('overview-facts');
    clear(tbody);
    [
        ['issuer', obj.issuer + (obj.issuer_pinned ? '  (pinned)' : '  (resolved from this host)')],
        ['mode', obj.standalone ? 'standalone - behind a proxy' : 'embedded'],
        ['admin credential', obj.admin_credential_set ? 'set' : 'NOT SET'],
        ['keys', obj.count_keys + ' in ' + obj.dir_keys],
        ['keys loaded', obj.keys_loaded],
        ['users', obj.count_users + ' in ' + obj.file_users],
        ['clients', obj.clients_strict
                ? obj.count_clients + ' registered - checked'
                : 'none registered - NOT checked'],
        ['default algorithm', obj.default_alg],
        ['default lifetime', obj.default_ttl_seconds + ' s']
    ].forEach(function (lstPair) {
        const tr = row(tbody);
        cell(tr, lstPair[0], 'name');
        cell(tr, lstPair[1], 'mono');
    });

    const tbodyUrl = el('overview-urls');
    clear(tbodyUrl);
    Object.keys(obj.urls).forEach(function (strName) {
        const tr = row(tbodyUrl);
        cell(tr, strName, 'name');
        cell(tr, obj.urls[strName], 'mono');
    });

    // THE WARNING IS NOT DECORATION. An unset credential means anyone who can
    // reach this service can change its keys and its users.
    const warn = el('overview-warn');
    warn.textContent = 'No admin credential is set, so key and user management'
            + ' are open to anyone who can reach this service. Set'
            + ' raposza.jwtmint.admin.password to close them.';
    show(warn, !obj.admin_credential_set);
};


// --------------------------------------------------------------------- keys

mapLoad.keys = async function () {
    const lst = await api('/api/ui/keys');
    const tbody = el('keys-rows');
    clear(tbody);

    lst.forEach(function (objKey) {
        const tr = row(tbody);
        cell(tr, objKey.kid, 'mono');
        cell(tr, objKey.alg);
        cell(tr, objKey.kty);
        cell(tr, objKey.detail);
        cell(tr, objKey.published ? 'yes' : 'no');
        cell(tr, objKey.thumbprint, 'mono');

        const tdAct = cell(tr, '', 'act');
        clear(tdAct);

        const btnRotate = document.createElement('button');
        btnRotate.type = 'button';
        btnRotate.className = 'secondary small';
        btnRotate.textContent = 'Rotate';
        btnRotate.onclick = function () {
            // A ROTATION INVALIDATES EVERY TOKEN ALREADY SIGNED with that key,
            // and this button sits beside Delete. It asks.
            if (!confirm('Rotate ' + objKey.kid + '?\n\nEvery token already'
                    + ' signed with it stops verifying, and every participant'
                    + ' holding the old public half has to re-read the JWKS.'))
                return;
            api('/api/ui/keys/' + encodeURIComponent(objKey.kid) + '/rotate',
                    {method: 'POST'})
                .then(mapLoad.keys).catch(ex => oops(ex.message));
        };
        tdAct.appendChild(btnRotate);

        if (!objKey.standard) {
            const btnDel = document.createElement('button');
            btnDel.type = 'button';
            btnDel.className = 'danger small';
            btnDel.textContent = 'Delete';
            btnDel.onclick = function () {
                if (!confirm('Delete ' + objKey.kid + '?'))
                    return;
                api('/api/ui/keys/' + encodeURIComponent(objKey.kid), {method: 'DELETE'})
                    .then(mapLoad.keys).catch(ex => oops(ex.message));
            };
            tdAct.appendChild(btnDel);
        }
    });
};


// -------------------------------------------------------------------- users

mapLoad.users = async function () {
    const obj = await api('/api/ui/users');
    el('users-file').textContent = obj.file;

    const tbody = el('users-rows');
    clear(tbody);

    obj.names.forEach(function (strName) {
        const tr = row(tbody);
        cell(tr, strName, 'mono');

        const tdAct = cell(tr, '', 'act');
        clear(tdAct);

        const btnDel = document.createElement('button');
        btnDel.type = 'button';
        btnDel.className = 'danger small';
        btnDel.textContent = 'Delete';
        btnDel.onclick = function () {
            if (!confirm('Delete the user ' + strName + '?'))
                return;
            api('/api/ui/users/' + encodeURIComponent(strName), {method: 'DELETE'})
                .then(mapLoad.users).catch(ex => oops(ex.message));
        };
        tdAct.appendChild(btnDel);
    });
};


// ------------------------------------------------------------------ clients

mapLoad.clients = async function () {
    const obj = await api('/api/ui/clients');

    // THE MODE LINE IS THE POINT OF THE PAGE. An empty registry is not an
    // empty table, it is a service that checks nothing.
    const mode = el('clients-mode');
    mode.className = obj.strict ? 'status ok' : 'status err';
    mode.textContent = obj.strict
            ? 'Checked. An unknown client_id, an unregistered redirect_uri and a'
                    + ' wrong client_secret are all refused. Store: ' + obj.file
            : 'NOT checked. Any client_id, any redirect_uri and any client_secret'
                    + ' are accepted - a real OpenID Provider refuses all three.'
                    + ' Register a client to close them.';
    show(mode, true);

    const tbody = el('clients-rows');
    clear(tbody);

    obj.clients.forEach(function (objClient) {
        const tr = row(tbody);
        cell(tr, objClient.client_id, 'mono');
        cell(tr, objClient.auth);
        cell(tr, objClient.redirect_uris.join('\n'), 'mono');

        const tdAct = cell(tr, '', 'act');
        clear(tdAct);

        const btnDel = document.createElement('button');
        btnDel.type = 'button';
        btnDel.className = 'danger small';
        btnDel.textContent = 'Delete';
        btnDel.onclick = function () {
            const strWarn = obj.clients.length === 1
                    ? '\n\nThis is the LAST client. Removing it reopens the'
                            + ' service: nothing will be checked.'
                    : '';
            if (!confirm('Remove the client ' + objClient.client_id + '?' + strWarn))
                return;
            api('/api/ui/clients/' + encodeURIComponent(objClient.client_id),
                    {method: 'DELETE'})
                .then(mapLoad.clients).catch(ex => oops(ex.message));
        };
        tdAct.appendChild(btnDel);
    });
};


// --------------------------------------------------------------------- mint

function strOrNull(strValue) {
    const strTrim = (strValue || '').trim();
    return strTrim === '' ? null : strTrim;
}


async function mint(ev) {
    ev.preventDefault();
    oops('');

    let objClaims = null;
    const strClaims = strOrNull(el('mint-claims').value);
    if (strClaims !== null) {
        try {
            objClaims = JSON.parse(strClaims);
        }
        catch (ex) {
            oops('the claims are not JSON: ' + ex.message);
            return;
        }
    }

    const strAud = strOrNull(el('mint-aud').value);
    const strTtl = strOrNull(el('mint-ttl').value);
    const body = {
        sub: strOrNull(el('mint-sub').value),
        aud: strAud === null ? null : [strAud],
        scope: strOrNull(el('mint-scope').value),
        alg: strOrNull(el('mint-alg').value),
        shape: strOrNull(el('mint-shape').value),
        ttlSeconds: strTtl === null ? null : Number(strTtl),
        claims: objClaims
    };

    try {
        // /mint IS NOT GUARDED and is not a UI-only path: this is the endpoint
        // a script uses, so the page cannot ask for anything a script cannot.
        const obj = await api('/mint', {method: 'POST', body: body});
        el('mint-token').value = obj.token;
        const out = el('mint-claims-out');
        out.textContent = JSON.stringify(obj.claims, null, 2);
        out.className = 'output ok';
        show(el('mint-out'), true);
    }
    catch (ex) {
        oops(ex.message);
    }
}


// ------------------------------------------------------------------ inspect

async function inspect(ev) {
    if (ev)
        ev.preventDefault();
    oops('');

    const obj = await api('/api/ui/inspect', {method: 'POST', body: {
        token: el('inspect-token').value,
        jwks: strOrNull(el('inspect-jwks').value)
    }});

    const verdict = el('inspect-verdict');
    const foreign = el('inspect-foreign');
    const tbody = el('inspect-facts');
    const claims = el('inspect-claims');
    clear(tbody);

    if (!obj.parsed) {
        verdict.className = 'status err';
        verdict.textContent = 'Not a signed JWT - ' + obj.detail;
        show(foreign, false);
        claims.textContent = '';
        claims.className = 'output err';
        show(el('inspect-out'), true);
        return;
    }

    verdict.className = obj.verified ? 'status ok' : 'status err';
    verdict.textContent = (obj.verified
            ? 'VERIFIED by this service\'s key set. '
            : 'NOT verified by this service\'s key set. ')
            + (obj.verified_detail || '');

    // THE FOREIGN ANSWER IS THE ONE THAT WAS ASKED FOR when a set was pasted,
    // so it is a line of its own rather than a row in the table.
    const flagForeign = obj.foreign_verified !== undefined;
    if (flagForeign) {
        foreign.className = obj.foreign_verified ? 'status ok' : 'status err';
        foreign.textContent = (obj.foreign_verified
                ? 'VERIFIED by the JWKS you pasted. '
                : 'NOT verified by the JWKS you pasted. ')
                + (obj.foreign_detail || '');
    }
    show(foreign, flagForeign);

    [
        ['alg', obj.alg],
        ['kid', obj.kid],
        ['iss', obj.issuer],
        ['sub', obj.subject],
        ['aud', (obj.audience || []).join(', ')],
        ['expires', obj.expires],
        ['expired', obj.expired ? 'YES' : 'no']
    ].forEach(function (lstPair) {
        const tr = row(tbody);
        cell(tr, lstPair[0], 'name');
        cell(tr, lstPair[1], 'mono');
    });

    if (flagForeign && obj.foreign_kids) {
        const tr = row(tbody);
        cell(tr, 'kids in that JWKS', 'name');
        cell(tr, obj.foreign_kids.join(', '), 'mono');
    }

    claims.textContent = JSON.stringify(obj.claims, null, 2);
    claims.className = 'output' + (obj.verified ? ' ok' : '');
    show(el('inspect-out'), true);
}


// ------------------------------------------------------------------- wiring

async function login(ev) {
    ev.preventDefault();
    const err = el('login-error');
    show(err, false);

    const res = await fetch('/api/ui/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            user: el('login-user').value,
            password: el('login-password').value
        })
    });

    if (!res.ok) {
        err.textContent = 'That is not the admin credential.';
        show(err, true);
        return;
    }
    el('login-password').value = '';
    showApp();
    selectTab('overview');
}


function wire() {
    const lstBtn = document.querySelectorAll('#tabs .seg-btn[data-tab]');
    for (let idx = 0; idx < lstBtn.length; idx++) {
        lstBtn[idx].onclick = function () {
            selectTab(this.dataset.tab);
        };
    }

    el('form-login').onsubmit = function (ev) {
        login(ev).catch(ex => oops(ex.message));
    };
    el('form-mint').onsubmit = mint;
    el('form-inspect').onsubmit = function (ev) {
        inspect(ev).catch(ex => oops(ex.message));
    };

    el('btn-signout').onclick = function () {
        api('/api/ui/logout', {method: 'POST'}).then(showGate).catch(showGate);
    };

    el('btn-keys-reload').onclick = function () {
        api('/api/ui/keys/reload', {method: 'POST'})
            .then(mapLoad.keys).catch(ex => oops(ex.message));
    };

    el('form-key-add').onsubmit = function (ev) {
        ev.preventDefault();
        api('/api/ui/keys', {method: 'POST', body: {
            kid: el('key-kid').value,
            alg: el('key-alg').value
        }}).then(function () {
            el('key-kid').value = '';
            return mapLoad.keys();
        }).catch(ex => oops(ex.message));
    };

    el('form-user').onsubmit = function (ev) {
        ev.preventDefault();
        api('/api/ui/users', {method: 'POST', body: {
            name: el('user-name').value,
            password: el('user-password').value
        }}).then(function () {
            el('user-name').value = '';
            el('user-password').value = '';
            return mapLoad.users();
        }).catch(ex => oops(ex.message));
    };

    el('form-client').onsubmit = function (ev) {
        ev.preventDefault();
        api('/api/ui/clients', {method: 'POST', body: {
            client_id: el('client-id').value,
            secret: el('client-secret').value,
            redirect_uris: el('client-uris').value
        }}).then(function () {
            el('client-id').value = '';
            el('client-secret').value = '';
            el('client-uris').value = '';
            return mapLoad.clients();
        }).catch(ex => oops(ex.message));
    };

    el('btn-mint-copy').onclick = function () {
        el('mint-token').select();
        document.execCommand('copy');
    };

    el('btn-mint-inspect').onclick = function () {
        el('inspect-token').value = el('mint-token').value;
        selectTab('inspect');
        inspect(null).catch(ex => oops(ex.message));
    };
}


// THE FIRST CALL DECIDES WHICH HALF OF THE PAGE IS SHOWN. With no credential
// configured it succeeds and the gate never appears; with one, it 401s and
// api() shows the gate.
wire();
mapLoad.overview().then(showApp).catch(function (ex) {
    if (ex.message !== 'sign in first')
        oops(ex.message);
});

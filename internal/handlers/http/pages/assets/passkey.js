// The one script of the identity service. It runs the WebAuthn ceremonies of
// the login pages and of the page of the passkeys. It has no third-party code.
// It sends the data of the browser to the service and shows the answer. All
// checks are on the server.
(function () {
  'use strict';

  var texts = {
    invalid_name: 'The name must have 1 to 64 characters, with no space at the start or the end, and no control characters',
    passkey_limit: 'You have the maximum number of passkeys',
    rate_limited: 'Too many requests. Try again later.',
    invalid_passkey: 'The passkey is not valid',
    expired: 'The request has expired. Try again.',
    unavailable: 'The service is not available. Try again later.',
    cancelled: 'The passkey request was cancelled or it timed out.',
    unsupported: 'This browser does not support passkeys.'
  };
  var unavailableText = 'The service is not available. Try again later.';

  function toBuffer(value) {
    var s = value.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4 !== 0) { s += '='; }
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
    return bytes.buffer;
  }

  function toBase64Url(buffer) {
    var bytes = new Uint8Array(buffer);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decodeDescriptors(list) {
    return (list || []).map(function (d) {
      var copy = {};
      for (var k in d) { if (Object.prototype.hasOwnProperty.call(d, k)) { copy[k] = d[k]; } }
      copy.id = toBuffer(d.id);
      return copy;
    });
  }

  function creationOptions(options) {
    var pk = options.publicKey;
    pk.challenge = toBuffer(pk.challenge);
    pk.user.id = toBuffer(pk.user.id);
    pk.excludeCredentials = decodeDescriptors(pk.excludeCredentials);
    return { publicKey: pk };
  }

  function requestOptions(options) {
    var pk = options.publicKey;
    pk.challenge = toBuffer(pk.challenge);
    pk.allowCredentials = decodeDescriptors(pk.allowCredentials);
    return { publicKey: pk };
  }

  function creationJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: toBase64Url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: {
        attestationObject: toBase64Url(r.attestationObject),
        clientDataJSON: toBase64Url(r.clientDataJSON),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : []
      },
      clientExtensionResults: {}
    };
  }

  function assertionJSON(cred) {
    var r = cred.response;
    var response = {
      authenticatorData: toBase64Url(r.authenticatorData),
      clientDataJSON: toBase64Url(r.clientDataJSON),
      signature: toBase64Url(r.signature)
    };
    if (r.userHandle && r.userHandle.byteLength > 0) { response.userHandle = toBase64Url(r.userHandle); }
    return {
      id: cred.id,
      rawId: toBase64Url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: response,
      clientExtensionResults: {}
    };
  }

  // post sends a JSON body with the cookies of the page. It resolves with the
  // status and the JSON body. A body that is not JSON gives an empty object.
  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (res) {
      return res.json().catch(function () { return null; }).then(function (data) {
        return { status: res.status, data: data };
      });
    });
  }

  function failure(answer) {
    var err = new Error('request failed');
    err.answer = answer;
    return err;
  }

  function checked(answer) {
    if (answer.status >= 200 && answer.status < 300 && answer.data) { return answer.data; }
    throw failure(answer);
  }

  function run(box) {
    var button = box.querySelector('.passkey-button');
    var out = box.querySelector('.passkey-error');
    var mode = box.getAttribute('data-passkey');
    var optionsURL = box.getAttribute('data-options');
    var finishURL = box.getAttribute('data-finish');
    var nameInput = box.querySelector('.passkey-name');
    if (!button) { return; }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      return;
    }
    button.hidden = false;

    function show(text) {
      if (!out) { return; }
      out.textContent = text;
      out.hidden = text === '';
    }

    function fail(err) {
      button.disabled = false;
      var answer = err && err.answer;
      if (answer) {
        var data = answer.data;
        if (data && data.error === 'login_required' && data.redirect) {
          window.location.assign(data.redirect);
          return;
        }
        if (data && texts[data.error]) { show(texts[data.error]); return; }
        show(unavailableText);
        return;
      }
      if (err && (err.name === 'NotAllowedError' || err.name === 'AbortError')) { show(texts.cancelled); return; }
      show(unavailableText);
    }

    button.addEventListener('click', function () {
      show('');
      button.disabled = true;
      var request = {};
      var ar = box.getAttribute('data-auth-request');
      var rt = box.getAttribute('data-return-to');
      if (ar) { request.authRequest = ar; }
      if (rt) { request.return_to = rt; }
      if (mode === 'register') { request.name = nameInput ? nameInput.value : ''; }

      post(optionsURL, request).then(checked).then(function (options) {
        if (mode === 'register') {
          return navigator.credentials.create(creationOptions(options)).then(function (cred) {
            if (!cred) { throw new Error('no credential'); }
            return creationJSON(cred);
          });
        }
        return navigator.credentials.get(requestOptions(options)).then(function (cred) {
          if (!cred) { throw new Error('no credential'); }
          return assertionJSON(cred);
        });
      }).then(function (body) {
        return post(finishURL, body);
      }).then(checked).then(function (data) {
        if (data.redirect) { window.location.assign(data.redirect); }
      }).catch(fail);
    });
  }

  var boxes = document.querySelectorAll('[data-passkey]');
  for (var i = 0; i < boxes.length; i++) { run(boxes[i]); }
}());

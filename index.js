const crypto = require('crypto');

module.exports.templateTags = [{
  name: 'request_signer',
  displayName: 'Request Signer',
  description: 'Generate and returns verification string.',

  async run (context) {
    let request = await context.util.models.request.getById(context.meta.requestId);
    let params = this.getParams(context, request);
    let endpoint = this.getEndpoint(context, request.url);
    let privateKey = context.context['private_key'];

    return this.generateVerification(params, endpoint, params['time'], params['key'], privateKey);
  },

  generateVerification (params, endpoint, unixTime, publicKey, privateKey) {
    params = [publicKey, unixTime, endpoint, this.urlEncode(params)];

    return crypto.createHmac('sha512', privateKey).update(params.join('|')).digest('hex');
  },

  urlEncode (data) {
    let key;
    let out = [];

    for (key in data) {
      out.push(key + '=' + encodeURIComponent(data[key]));
    }

    return out.join('&');
  },

  getDataValue (context, value) {
    if (value.startsWith("{{") && value.endsWith("}}")) {
      return context.context[value.replace(/[{}]/g, '').trim()];
    }

    return value;
  },

  getEndpoint (context, url) {
    if (url.startsWith("{{")) {
      return url.replace(/\s?\{[^}]+\}\}/g, '').trim();
    }

    let baseUrl = context.context['base_url'];

    return url.replace(baseUrl, '').trim();
  },

  getParams (context, request) {
    let requestParams = request.parameters;
    let params = [];
    let index;

    if (request.method == 'POST') {
      requestParams = request.body.params;
    }

    for (index in requestParams) {
      if (requestParams[index].name == 'verification') {
        continue;
      }

      params[requestParams[index].name] = this.getDataValue(context, requestParams[index].value);
    }

    return params;
  }
}];

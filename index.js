const crypto = require('crypto');

module.exports.templateTags = [{
  name: 'request_signer',
  displayName: 'Request Signer',
  description: 'Generate verification string',
  args: [
      {
        displayName: 'Endpoint',
        description: 'The endpoint you are accessing',
        type: 'string',
        defaultValue: '/api/some/endpoint'
      },
      {
          displayName: 'Public Key',
          description: 'Your public key',
          type: 'string',
          defaultValue: 'abcdefg'
      },
      {
        displayName: 'Private Key',
        description: 'Your private key',
        type: 'string',
        defaultValue: '1234567'
      },
      {
        displayName: 'Time',
        description: 'The current UNIX time.',
        type: 'string',
        defaultValue: '946684800'
      },
      {
        displayName: 'Data',
        description: 'The payload',
        type: 'string',
        defaultValue: '{}'
      }
  ],

  async run (context, endpoint, publicKey, privateKey, unixTime, data) {
    let params = JSON.parse(data)
    params['key'] = publicKey
    params['time'] = unixTime

    let verification = this.generateVerification(params, endpoint, unixTime, publicKey, privateKey)

    return verification
  },

  generateVerification (params, endpoint, unixTime, publicKey, privateKey) {
    params = [publicKey, unixTime, endpoint, this.urlEncode(params)]

    return crypto.createHmac('sha512', privateKey).update(params.join('|')).digest('hex')
  },

  urlEncode (data) {
    let key
    let out = new Array()

    for (key in data) {
      out.push(key + '=' + encodeURIComponent(data[key]))
    }

    return out.join('&')
  }
}];

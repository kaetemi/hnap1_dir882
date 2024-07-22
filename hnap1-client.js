const axios = require('axios');
const crypto = require('crypto');
const xml2js = require('xml2js');

// This MD5 implementation is required for compatibility.
// Standard Node.js crypto functions produce different results,
// likely due to variations in input processing or HMAC construction.
// Router expects this specific HMAC-MD5 implementation.
const hex_hmac_md5 = require('./md5').hex_hmac_md5;

/**
 * HNAP1Client class for interacting with D-Link DIR-882 routers using the HNAP1 protocol.
 */
class HNAP1Client {
  /**
   * Create a new HNAP1Client instance.
   * @param {string} routerIP - The IP address of the router.
   * @param {string} username - The username for router authentication.
   * @param {string} password - The password for router authentication.
   */
  constructor(routerIP, username, password) {
    this.routerIP = routerIP;
    this.username = username;
    this.password = password;
    this.baseUrl = `http://${routerIP}/HNAP1/`;
    this.privateKey = null;
    this.cookie = null;
    this.publicKey = null;
    this.challenge = null;
    this.compareTimeStamp = 0;
  }

  /**
   * Perform the two-step login process.
   * @returns {Promise<void>}
   */
  async login() {
    await this.requestLoginChallenge();
    await this.performLogin();
  }

  /**
   * Request the login challenge from the router.
   * @returns {Promise<void>}
   */
  async requestLoginChallenge() {
    const action = 'Login';
    const body = this.createSOAP(action, {
      Action: 'request',
      Username: this.username,
      LoginPassword: '',
      Captcha: ''
    });

    const response = await this.makeHNAPRequest(action, body);
    const result = await this.parseXmlResponse(response);

    this.challenge = result.Challenge;
    this.cookie = result.Cookie;
    this.publicKey = result.PublicKey;

    if (!this.challenge || !this.cookie || !this.publicKey) {
      throw new Error('Login challenge request failed');
    }
  }

  /**
   * Perform the login using the challenge response.
   * @returns {Promise<void>}
   */
  async performLogin() {
    const action = 'Login';
    this.privateKey = this.generatePrivateKey();
    const loginPassword = this.generateLoginPassword();

    const body = this.createSOAP(action, {
      Action: 'login',
      Username: this.username,
      LoginPassword: loginPassword,
      Captcha: ''
    });

    const response = await this.makeHNAPRequest(action, body);
    const result = await this.parseXmlResponse(response);

    if (result.LoginResult !== 'success') {
      throw new Error('Login failed');
    }
  }

  /**
   * Generate the private key using the challenge, public key, and password.
   * @returns {string} The generated private key.
   */
  generatePrivateKey() {
    return hex_hmac_md5(this.publicKey + this.password, this.challenge).toUpperCase();
  }

  /**
   * Generate the login password hash required for HNAP1 authentication.
   * @returns {string} The hashed login password.
   */
  generateLoginPassword() {
      return hex_hmac_md5(this.privateKey, this.challenge).toUpperCase();
  }

  /**
   * Generate the HNAP_AUTH header value.
   * @param {string} soapAction - The SOAP action being performed.
   * @returns {string} The HNAP_AUTH header value.
   */
  generateHnapAuth(soapAction) {
    const timestamp = this.getUniqueTimestamp();
    const auth = hex_hmac_md5(this.privateKey, timestamp + soapAction).toUpperCase();
    return `${auth} ${timestamp}`;
  }

  /**
   * Get a unique timestamp for each request.
   * @returns {string} A unique timestamp.
   */
  getUniqueTimestamp() {
    let timestamp = Math.floor(Date.now() % 2000000000000);
    if (this.compareTimeStamp === timestamp) {
      timestamp += 1;
    }
    this.compareTimeStamp = timestamp;
    return timestamp.toString();
  }

  /**
   * Make an HNAP request to the router.
   * @param {string} action - The HNAP action to perform.
   * @param {string} body - The XML body of the request.
   * @returns {Promise<string>} A promise that resolves to the raw XML response.
   */
  async makeHNAPRequest(action, body) {
    const soapAction = `"http://purenetworks.com/HNAP1/${action}"`;
    const headers = {
      'Content-Type': 'text/xml; charset=utf-8',
      'SOAPAction': soapAction,
    };

    if (this.privateKey) {
      headers['HNAP_AUTH'] = this.generateHnapAuth(soapAction);
    }

    if (this.cookie) {
      headers['Cookie'] = `uid=${this.cookie}`;
    }

    try {
      const response = await axios.post(this.baseUrl, body, { headers });
      return response.data;
    } catch (error) {
      throw new Error(`HNAP request failed: ${error.message}`);
    }
  }

  /**
   * Create a SOAP envelope for an HNAP request.
   * @param {string} action - The HNAP action.
   * @param {Object} params - The parameters for the action.
   * @returns {string} The SOAP envelope.
   */
  createSOAP(action, params) {
    let xmlBody = `<?xml version="1.0" encoding="utf-8"?>
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                     xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <${action} xmlns="http://purenetworks.com/HNAP1/">`;

    for (const [key, value] of Object.entries(params)) {
      xmlBody += `<${key}>${value}</${key}>`;
    }

    xmlBody += `</${action}>
        </soap:Body>
      </soap:Envelope>`;

    return xmlBody;
  }

  /**
   * Parse an XML response into a JavaScript object using xml2js.
   * @param {string} xmlString - The XML string to parse.
   * @returns {Promise<Object>} A promise that resolves to the parsed JavaScript object.
   */
  async parseXmlResponse(xmlString) {
    const parser = new xml2js.Parser({
      explicitArray: false,
      ignoreAttrs: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    });

    try {
      const result = await parser.parseStringPromise(xmlString);
      const envelope = result.Envelope;
      if (!envelope || !envelope.Body) {
        throw new Error('Invalid SOAP response: Envelope or Body not found');
      }

      // Get the first key in the Body object (should be the response element)
      const responseKey = Object.keys(envelope.Body)[0];
      return envelope.Body[responseKey];
    } catch (error) {
      throw new Error(`XML parsing failed: ${error.message}`);
    }
  }

  /**
   * Get the device settings from the router.
   * @returns {Promise<Object>} A promise that resolves to the parsed device settings.
   */
  async getDeviceSettings() {
    const action = 'GetDeviceSettings';
    const body = this.createSOAP(action, {});
    const response = await this.makeHNAPRequest(action, body);
    return await this.parseXmlResponse(response);
  }

  /**
   * Get the WAN settings from the router.
   * @returns {Promise<Object>} A promise that resolves to the parsed WAN settings.
   */
  async getWanSettings() {
    const action = 'GetWanSettings';
    const body = this.createSOAP(action, {});
    const response = await this.makeHNAPRequest(action, body);
    return await this.parseXmlResponse(response);
  }

  /**
   * Get the wireless settings from the router.
   * @param {string} radio - The radio to get settings for (e.g., "RADIO_2.4GHz" or "RADIO_5GHz").
   * @returns {Promise<Object>} A promise that resolves to the parsed wireless settings.
   */
  async getWirelessSettings(radio) {
    const action = 'GetWLanRadioSettings';
    const body = this.createSOAP(action, { RadioID: radio });
    const response = await this.makeHNAPRequest(action, body);
    return await this.parseXmlResponse(response);
  }

  /**
   * Get the list of connected clients.
   * @returns {Promise<Object>} A promise that resolves to the parsed list of connected clients.
   */
  async getConnectedClients() {
    const action = 'GetClientInfo';
    const body = this.createSOAP(action, {});
    const response = await this.makeHNAPRequest(action, body);
    return await this.parseXmlResponse(response);
  }

  /**
   * Reboot the router.
   * @returns {Promise<Object>} A promise that resolves to the reboot operation result.
   */
  async reboot() {
    const action = 'Reboot';
    const body = this.createSOAP(action, {});
    const response = await this.makeHNAPRequest(action, body);
    return await this.parseXmlResponse(response);
  }
}

module.exports = HNAP1Client;

/* end of file */
